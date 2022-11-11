use super::{
	AccountId, Balances, Call, Event, Origin, ParachainInfo, ParachainSystem, PolkadotXcm, Runtime,
	WeightToFee, XcmpQueue,
};
use core::marker::PhantomData;
use frame_support::{
	log, match_types, parameter_types,
	traits::{EnsureOrigin, EnsureOriginWithArg, Everything, Nothing},
};
use orml_traits::asset_registry::{AssetMetadata, AssetProcessor};
use pallet_xcm::XcmPassthrough;
use polkadot_parachain::primitives::Sibling;
use polkadot_runtime_common::impls::ToAuthor;
#[cfg(feature = "std")]
use serde::{Deserialize, Serialize};
use xcm::latest::{prelude::*, Weight as XCMWeight};
use xcm_builder::{
	AccountId32Aliases, AllowTopLevelPaidExecutionFrom, AllowUnpaidExecutionFrom, CurrencyAdapter,
	EnsureXcmOrigin, FixedWeightBounds, IsConcrete, LocationInverter, NativeAsset, ParentIsPreset,
	RelayChainAsNative, SiblingParachainAsNative, SiblingParachainConvertsVia,
	SignedAccountId32AsNative, SignedToAccountId32, SovereignSignedViaLocation, TakeWeightCredit,
	UsingComponents,
};

use sp_runtime::DispatchError;

use codec::{Decode, Encode, MaxEncodedLen};
use scale_info::TypeInfo;
use xcm_executor::{traits::ShouldExecute, XcmExecutor};

use super::Balance;
use frame_system::{EnsureRoot, RawOrigin};

parameter_types! {
	pub const RelayLocation: MultiLocation = MultiLocation::parent();
	pub const RelayNetwork: NetworkId = NetworkId::Any;
	pub RelayChainOrigin: Origin = cumulus_pallet_xcm::Origin::Relay.into();
	pub Ancestry: MultiLocation = Parachain(ParachainInfo::parachain_id().into()).into();
}

/// Type for specifying how a `MultiLocation` can be converted into an `AccountId`. This is used
/// when determining ownership of accounts for asset transacting and when attempting to use XCM
/// `Transact` in order to determine the dispatch Origin.
pub type LocationToAccountId = (
	// The parent (Relay-chain) origin converts to the parent `AccountId`.
	ParentIsPreset<AccountId>,
	// Sibling parachain origins convert to AccountId via the `ParaId::into`.
	SiblingParachainConvertsVia<Sibling, AccountId>,
	// Straight up local `AccountId32` origins just alias directly to `AccountId`.
	AccountId32Aliases<RelayNetwork, AccountId>,
);

/// Means for transacting assets on this chain.
pub type LocalAssetTransactor = CurrencyAdapter<
	// Use this currency:
	Balances,
	// Use this currency when it is a fungible asset matching the given location or name:
	IsConcrete<RelayLocation>,
	// Do a simple punn to convert an AccountId32 MultiLocation into a native chain account ID:
	LocationToAccountId,
	// Our chain's account ID type (we can't get away without mentioning it explicitly):
	AccountId,
	// We don't track any teleports.
	(),
>;

/// This is the type we use to convert an (incoming) XCM origin into a local `Origin` instance,
/// ready for dispatching a transaction with Xcm's `Transact`. There is an `OriginKind` which can
/// biases the kind of local `Origin` it will become.
pub type XcmOriginToTransactDispatchOrigin = (
	// Sovereign account converter; this attempts to derive an `AccountId` from the origin location
	// using `LocationToAccountId` and then turn that into the usual `Signed` origin. Useful for
	// foreign chains who want to have a local sovereign account on this chain which they control.
	SovereignSignedViaLocation<LocationToAccountId, Origin>,
	// Native converter for Relay-chain (Parent) location; will converts to a `Relay` origin when
	// recognized.
	RelayChainAsNative<RelayChainOrigin, Origin>,
	// Native converter for sibling Parachains; will convert to a `SiblingPara` origin when
	// recognized.
	SiblingParachainAsNative<cumulus_pallet_xcm::Origin, Origin>,
	// Native signed account converter; this just converts an `AccountId32` origin into a normal
	// `Origin::Signed` origin of the same 32-byte value.
	SignedAccountId32AsNative<RelayNetwork, Origin>,
	// Xcm origins can be represented natively under the Xcm pallet's Xcm origin.
	XcmPassthrough<Origin>,
);

parameter_types! {
	// One XCM operation is 1_000_000_000 weight - almost certainly a conservative estimate.
	pub UnitWeightCost: u64 = 1_000_000_000;
	pub const MaxInstructions: u32 = 100;
}

match_types! {
	pub type ParentOrParentsExecutivePlurality: impl Contains<MultiLocation> = {
		MultiLocation { parents: 1, interior: Here } |
		MultiLocation { parents: 1, interior: X1(Plurality { id: BodyId::Executive, .. }) }
	};
}

//TODO: move DenyThenTry to polkadot's xcm module.
/// Deny executing the xcm message if it matches any of the Deny filter regardless of anything else.
/// If it passes the Deny, and matches one of the Allow cases then it is let through.
pub struct DenyThenTry<Deny, Allow>(PhantomData<Deny>, PhantomData<Allow>)
where
	Deny: ShouldExecute,
	Allow: ShouldExecute;

impl<Deny, Allow> ShouldExecute for DenyThenTry<Deny, Allow>
where
	Deny: ShouldExecute,
	Allow: ShouldExecute,
{
	fn should_execute<Call>(
		origin: &MultiLocation,
		message: &mut Xcm<Call>,
		max_weight: XCMWeight,
		weight_credit: &mut XCMWeight,
	) -> Result<(), ()> {
		Deny::should_execute(origin, message, max_weight, weight_credit)?;
		Allow::should_execute(origin, message, max_weight, weight_credit)
	}
}

// See issue #5233
pub struct DenyReserveTransferToRelayChain;
impl ShouldExecute for DenyReserveTransferToRelayChain {
	fn should_execute<Call>(
		origin: &MultiLocation,
		message: &mut Xcm<Call>,
		_max_weight: XCMWeight,
		_weight_credit: &mut XCMWeight,
	) -> Result<(), ()> {
		if message.0.iter().any(|inst| {
			matches!(
				inst,
				InitiateReserveWithdraw {
					reserve: MultiLocation { parents: 1, interior: Here },
					..
				} | DepositReserveAsset { dest: MultiLocation { parents: 1, interior: Here }, .. } |
					TransferReserveAsset {
						dest: MultiLocation { parents: 1, interior: Here },
						..
					}
			)
		}) {
			return Err(()) // Deny
		}

		// An unexpected reserve transfer has arrived from the Relay Chain. Generally, `IsReserve`
		// should not allow this, but we just log it here.
		if matches!(origin, MultiLocation { parents: 1, interior: Here }) &&
			message.0.iter().any(|inst| matches!(inst, ReserveAssetDeposited { .. }))
		{
			log::warn!(
				target: "xcm::barriers",
				"Unexpected ReserveAssetDeposited from the Relay Chain",
			);
		}
		// Permit everything else
		Ok(())
	}
}

pub type Barrier = DenyThenTry<
	DenyReserveTransferToRelayChain,
	(
		TakeWeightCredit,
		AllowTopLevelPaidExecutionFrom<Everything>,
		AllowUnpaidExecutionFrom<ParentOrParentsExecutivePlurality>,
		// ^^^ Parent and its exec plurality get free execution
	),
>;

pub struct XcmConfig;
impl xcm_executor::Config for XcmConfig {
	type Call = Call;
	type XcmSender = XcmRouter;
	// How to withdraw and deposit an asset.
	type AssetTransactor = LocalAssetTransactor;
	type OriginConverter = XcmOriginToTransactDispatchOrigin;
	type IsReserve = NativeAsset;
	type IsTeleporter = (); // Teleporting is disabled.
	type LocationInverter = LocationInverter<Ancestry>;
	type Barrier = Barrier;
	type Weigher = FixedWeightBounds<UnitWeightCost, Call, MaxInstructions>;
	type Trader =
		UsingComponents<WeightToFee, RelayLocation, AccountId, Balances, ToAuthor<Runtime>>;
	type ResponseHandler = PolkadotXcm;
	type AssetTrap = PolkadotXcm;
	type AssetClaims = PolkadotXcm;
	type SubscriptionService = PolkadotXcm;
}

/// No local origins on this chain are allowed to dispatch XCM sends/executions.
pub type LocalOriginToLocation = SignedToAccountId32<Origin, AccountId, RelayNetwork>;

/// The means for routing XCM messages which are not for local execution into the right message
/// queues.
pub type XcmRouter = (
	// Two routers - use UMP to communicate with the relay chain:
	cumulus_primitives_utility::ParentAsUmp<ParachainSystem, ()>,
	// ..and XCMP to communicate with the sibling chains.
	XcmpQueue,
);

impl pallet_xcm::Config for Runtime {
	type Event = Event;
	type SendXcmOrigin = EnsureXcmOrigin<Origin, LocalOriginToLocation>;
	type XcmRouter = XcmRouter;
	type ExecuteXcmOrigin = EnsureXcmOrigin<Origin, LocalOriginToLocation>;
	type XcmExecuteFilter = Nothing;
	// ^ Disable dispatchable execute on the XCM pallet.
	// Needs to be `Everything` for local testing.
	type XcmExecutor = XcmExecutor<XcmConfig>;
	type XcmTeleportFilter = Everything;
	type XcmReserveTransferFilter = Nothing;
	type Weigher = FixedWeightBounds<UnitWeightCost, Call, MaxInstructions>;
	type LocationInverter = LocationInverter<Ancestry>;
	type Origin = Origin;
	type Call = Call;

	const VERSION_DISCOVERY_QUEUE_SIZE: u32 = 100;
	// ^ Override for AdvertisedXcmVersion default
	type AdvertisedXcmVersion = pallet_xcm::CurrentXcmVersion;
}

impl cumulus_pallet_xcm::Config for Runtime {
	type Event = Event;
	type XcmExecutor = XcmExecutor<XcmConfig>;
}

pub type ForeignAssetId = u32;

#[derive(
	Clone, Copy, PartialOrd, Ord, PartialEq, Eq, Debug, Encode, Decode, TypeInfo, MaxEncodedLen,
)]
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
pub enum CurrencyId {
	Native,
	// Karura KSM
	KSM,
	// Karura Dollar
	AUSD,
	KAR,
	MGX,
	ForeignAsset(ForeignAssetId),
	Default,
}

impl Default for CurrencyId {
	fn default() -> Self {
		CurrencyId::Native
	}
}

#[derive(
	Clone, Copy, PartialOrd, Ord, PartialEq, Eq, Debug, Encode, Decode, TypeInfo, MaxEncodedLen,
)]
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
pub struct CustomMetadata {
	/// XCM-related metadata.
	/// XCM-related metadata, optional.
	pub xcm: XcmMetadata,
}

#[derive(
	Clone, Copy, PartialOrd, Ord, PartialEq, Eq, Debug, Encode, Decode, TypeInfo, MaxEncodedLen,
)]
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
pub struct XcmMetadata {
	/// The fee charged for every second that an XCM message takes to execute.
	pub fee_per_second: Option<u128>,
}

pub struct CustomAssetProcessor;

impl AssetProcessor<CurrencyId, AssetMetadata<Balance, CustomMetadata>> for CustomAssetProcessor {
	fn pre_register(
		id: Option<CurrencyId>,
		metadata: AssetMetadata<Balance, CustomMetadata>,
	) -> Result<(CurrencyId, AssetMetadata<Balance, CustomMetadata>), DispatchError> {
		match id {
			Some(id) => Ok((id, metadata)),
			None => Err(DispatchError::Other("asset-registry: AssetId is required")),
		}
	}

	fn post_register(
		_id: CurrencyId,
		_asset_metadata: AssetMetadata<Balance, CustomMetadata>,
	) -> Result<(), DispatchError> {
		Ok(())
	}
}

/// The OrmlAssetRegistry::AuthorityOrigin impl
pub struct AuthorityOrigin<
	// The origin type
	Origin,
	// The default EnsureOrigin impl used to authorize all
	// assets besides tranche tokens.
	DefaultEnsureOrigin,
>(PhantomData<(Origin, DefaultEnsureOrigin)>);

impl<
		Origin: Into<Result<RawOrigin<AccountId>, Origin>> + From<RawOrigin<AccountId>>,
		DefaultEnsureOrigin: EnsureOrigin<Origin>,
	> EnsureOriginWithArg<Origin, Option<CurrencyId>> for AuthorityOrigin<Origin, DefaultEnsureOrigin>
{
	type Success = ();

	fn try_origin(origin: Origin, asset_id: &Option<CurrencyId>) -> Result<Self::Success, Origin> {
		match asset_id {
			// Any other `asset_id` defaults to EnsureRoot
			_ => DefaultEnsureOrigin::try_origin(origin).map(|_| ()),
		}
	}

	#[cfg(feature = "runtime-benchmarks")]
	fn successful_origin(_asset_id: &Option<CurrencyId>) -> Origin {
		unimplemented!()
	}
}

impl orml_asset_registry::Config for Runtime {
	type AssetId = CurrencyId;
	type AssetProcessor = CustomAssetProcessor;
	type AuthorityOrigin = AuthorityOrigin<Origin, EnsureRoot<AccountId>>;
	type Balance = Balance;
	type CustomMetadata = CustomMetadata;
	type Event = Event;
	type WeightInfo = ();
}

// pub type LocalAssetTransactor = MultiCurrencyAdapter<
// 	Currencies,
// 	UnknownTokens,
// 	IsNativeConcrete<CurrencyId, CurrencyIdConvert>,
// 	AccountId,
// 	LocationToAccountId,
// 	CurrencyId,
// 	CurrencyIdConvert,
// 	DepositToAlternative<AcalaTreasuryAccount, Currencies, CurrencyId, AccountId, Balance>,
// >;

// pub struct CurrencyIdConvert;
// impl Convert<CurrencyId, Option<MultiLocation>> for CurrencyIdConvert {
// 	fn convert(id: CurrencyId) -> Option<MultiLocation> {
// 		use primitives::TokenSymbol::*;
// 		use CurrencyId::{Erc20, ForeignAsset, LiquidCrowdloan, StableAssetPoolToken, Token};
// 		match id {
// 			Token(DOT) => Some(MultiLocation::parent()),
// 			Token(ACA) | Token(AUSD) | Token(LDOT) | Token(TAP) =>
// 				Some(native_currency_location(ParachainInfo::get().into(), id.encode())),
// 			Erc20(address) if !is_system_contract(address) =>
// 				Some(native_currency_location(ParachainInfo::get().into(), id.encode())),
// 			LiquidCrowdloan(_lease) =>
// 				Some(native_currency_location(ParachainInfo::get().into(), id.encode())),
// 			StableAssetPoolToken(_pool_id) =>
// 				Some(native_currency_location(ParachainInfo::get().into(), id.encode())),
// 			ForeignAsset(foreign_asset_id) =>
// 				AssetIdMaps::<Runtime>::get_multi_location(foreign_asset_id),
// 			_ => None,
// 		}
// 	}
// }
// impl Convert<MultiLocation, Option<CurrencyId>> for CurrencyIdConvert {
// 	fn convert(location: MultiLocation) -> Option<CurrencyId> {
// 		use primitives::TokenSymbol::*;
// 		use CurrencyId::{Erc20, LiquidCrowdloan, StableAssetPoolToken, Token};

// 		if location == MultiLocation::parent() {
// 			return Some(Token(DOT))
// 		}

// 		if let Some(currency_id) = AssetIdMaps::<Runtime>::get_currency_id(location.clone()) {
// 			return Some(currency_id)
// 		}

// 		match location {
// 			MultiLocation { parents, interior: X2(Parachain(para_id), GeneralKey(key)) }
// 				if parents == 1 =>
// 			{
// 				match (para_id, &key.into_inner()[..]) {
// 					(id, key) if id == u32::from(ParachainInfo::get()) => {
// 						// Acala
// 						if let Ok(currency_id) = CurrencyId::decode(&mut &*key) {
// 							// check `currency_id` is cross-chain asset
// 							match currency_id {
// 								Token(ACA) | Token(AUSD) | Token(LDOT) | Token(TAP) =>
// 									Some(currency_id),
// 								Erc20(address) if !is_system_contract(address) => Some(currency_id),
// 								LiquidCrowdloan(_lease) => Some(currency_id),
// 								StableAssetPoolToken(_pool_id) => Some(currency_id),
// 								_ => None,
// 							}
// 						} else {
// 							// invalid general key
// 							None
// 						}
// 					},
// 					_ => None,
// 				}
// 			},
// 			// adapt for re-anchor canonical location: https://github.com/paritytech/polkadot/pull/4470
// 			MultiLocation { parents: 0, interior: X1(GeneralKey(key)) } => {
// 				let key = &key.into_inner()[..];
// 				let currency_id = CurrencyId::decode(&mut &*key).ok()?;
// 				match currency_id {
// 					Token(ACA) | Token(AUSD) | Token(LDOT) | Token(TAP) => Some(currency_id),
// 					Erc20(address) if !is_system_contract(address) => Some(currency_id),
// 					LiquidCrowdloan(_lease) => Some(currency_id),
// 					StableAssetPoolToken(_pool_id) => Some(currency_id),
// 					_ => None,
// 				}
// 			},
// 			_ => None,
// 		}
// 	}
// }
// impl Convert<MultiAsset, Option<CurrencyId>> for CurrencyIdConvert {
// 	fn convert(asset: MultiAsset) -> Option<CurrencyId> {
// 		if let MultiAsset { id: Concrete(location), .. } = asset {
// 			Self::convert(location)
// 		} else {
// 			None
// 		}
// 	}
// }

// parameter_types! {
// 	pub SelfLocation: MultiLocation = MultiLocation::new(1, X1(Parachain(ParachainInfo::get().into())));
// }

// pub struct AccountIdToMultiLocation;
// impl Convert<AccountId, MultiLocation> for AccountIdToMultiLocation {
// 	fn convert(account: AccountId) -> MultiLocation {
// 		X1(AccountId32 { network: NetworkId::Any, id: account.into() }).into()
// 	}
// }

// parameter_types! {
// 	pub const BaseXcmWeight: Weight = 100_000_000; // TODO: recheck this
// 	pub const MaxAssetsForTransfer: usize = 2;
// }

// parameter_type_with_key! {
// 	pub ParachainMinFee: |location: MultiLocation| -> Option<u128> {
// 		#[allow(clippy::match_ref_pats)] // false positive
// 		match (location.parents, location.first_interior()) {
// 			(1, Some(Parachain(parachains::statemint::ID))) => Some(XcmInterface::get_parachain_fee(location.clone())),
// 			_ => None,
// 		}
// 	};
// }

// impl orml_xtokens::Config for Runtime {
// 	type Event = Event;
// 	type Balance = Balance;
// 	type CurrencyId = CurrencyId;
// 	type CurrencyIdConvert = CurrencyIdConvert;
// 	type AccountIdToMultiLocation = AccountIdToMultiLocation;
// 	type SelfLocation = SelfLocation;
// 	type XcmExecutor = XcmExecutor<XcmConfig>;
// 	type Weigher = FixedWeightBounds<UnitWeightCost, Call, MaxInstructions>;
// 	type BaseXcmWeight = BaseXcmWeight;
// 	type LocationInverter = LocationInverter<Ancestry>;
// 	type MaxAssetsForTransfer = MaxAssetsForTransfer;
// 	type MinXcmFee = ParachainMinFee;
// 	type MultiLocationsFilter = Everything;
// 	type ReserveProvider = AbsoluteReserveProvider;
// }
