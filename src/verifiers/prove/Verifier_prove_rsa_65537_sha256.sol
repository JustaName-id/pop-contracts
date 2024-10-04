// SPDX-License-Identifier: GPL-3.0
/*
    Copyright 2021 0KIMS association.

    This file is generated with [snarkJS](https://github.com/iden3/snarkjs).

    snarkJS is a free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    snarkJS is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General Public License
    along with snarkJS. If not, see <https://www.gnu.org/licenses/>.
*/

pragma solidity >=0.7.0 <0.9.0;

contract VerifierProveRSA65537SHA256 {
    // Scalar field size
    uint256 constant r = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    // Base field size
    uint256 constant q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;

    // Verification Key data
    uint256 constant alphax = 20491192805390485299153009773594534940189261866228447918068658471970481763042;
    uint256 constant alphay = 9383485363053290200918347156157836566562967994039712273449902621266178545958;
    uint256 constant betax1 = 4252822878758300859123897981450591353533073413197771768651442665752259397132;
    uint256 constant betax2 = 6375614351688725206403948262868962793625744043794305715222011528459656738731;
    uint256 constant betay1 = 21847035105528745403288232691147584728191162732299865338377159692350059136679;
    uint256 constant betay2 = 10505242626370262277552901082094356697409835680220590971873171140371331206856;
    uint256 constant gammax1 = 11559732032986387107991004021392285783925812861821192530917403151452391805634;
    uint256 constant gammax2 = 10857046999023057135944570762232829481370756359578518086990519993285655852781;
    uint256 constant gammay1 = 4082367875863433681332203403145435568316851327593401208105741076214120093531;
    uint256 constant gammay2 = 8495653923123431417604973247489272438418190587263600148770280649306958101930;
    uint256 constant deltax1 = 14592040466721897410751298364990054214451540028888985062695172395838725424775;
    uint256 constant deltax2 = 15481924837432160208872655385705250492908504698994723813870899743593513641572;
    uint256 constant deltay1 = 21246867117655718260917042108944144450999411575535552904993777381079254412022;
    uint256 constant deltay2 = 14916040524845705880889946137582678766123012127363811401979597838770949742165;

    uint256 constant IC0x = 18380815265546900532609012343679796317016693242479521843893867424817014804563;
    uint256 constant IC0y = 12945373739259800312407088410190974601829488713074914745262778532321930640784;

    uint256 constant IC1x = 8289753245441895144484429024321697059528026779869639381182374356067434337897;
    uint256 constant IC1y = 12562053258734156210483450241839384859900028537373915146945482378765594620669;

    uint256 constant IC2x = 18906773082666392477483580166517493763001472360067206874454453197336618552663;
    uint256 constant IC2y = 11633326657090810106163852955450702271273233459423307004749566157990182634319;

    uint256 constant IC3x = 15071464215477902590557024698659546147208186489485741828127201059014248867358;
    uint256 constant IC3y = 11676164727487098035768713275808048094225894814285541970945526316435090957616;

    uint256 constant IC4x = 13744519314898267949239485317013802858624286381261977893681030793438027878070;
    uint256 constant IC4y = 14960564678088629342792129505187002991792418283404624680537018156270760587901;

    uint256 constant IC5x = 10462045376103480927242088410816620043408234275417611728684392797800304310963;
    uint256 constant IC5y = 15366488206242116061604608092616392954988966780642564127920812830118020554925;

    uint256 constant IC6x = 14493238824243525984116304385477257290183123409304697794103835867178980066857;
    uint256 constant IC6y = 17125008140311563076336886118578087185158542679112811254861084070839359172167;

    uint256 constant IC7x = 9177478023346553579719988159422336653000751295563920114345799168258400154877;
    uint256 constant IC7y = 9068318710239000407250874771465209707733633593133309188401681124982484862231;

    uint256 constant IC8x = 11514933794695447147916148959272717813617424459862806248630662155761122525479;
    uint256 constant IC8y = 15672653287986461383197473535754725929681496991616892145242809046953903204666;

    uint256 constant IC9x = 19381464447700196447664207595439153301395188399685827014251925880176965135693;
    uint256 constant IC9y = 3460444376114301095449415169893162946367763782283301426392852057315274316163;

    uint256 constant IC10x = 140133487444907374415019567988478860151645951831962627621629422704867577895;
    uint256 constant IC10y = 6499881224669121585190396054356783144767776536927354492262035974085409195309;

    uint256 constant IC11x = 1076047573537315785523828691913445365008912255302298797024922902728347119943;
    uint256 constant IC11y = 14365898549860972963129409702786698480434022164712926094512318819928948646828;

    uint256 constant IC12x = 11807167026188224854495171439201946236068720158465356825832886671211597705306;
    uint256 constant IC12y = 6257912383484238138063251524568714760122912251094284411861832959252986206049;

    uint256 constant IC13x = 21064912794316265557281896561746517126007132844045326276114903600581984770646;
    uint256 constant IC13y = 15448853591808190201080587968765504991020973707178811680431195475059709249817;

    uint256 constant IC14x = 7117660282995201015941724102091931669931464947868779524942589847804182256643;
    uint256 constant IC14y = 17614023776111615908749073841558687987784064329294245943645965415567327929005;

    uint256 constant IC15x = 8664818028046597564734932728939722952580847319960715231777173058519030707860;
    uint256 constant IC15y = 1122767192206894615376228243439126718840640518177251993643924937017210730055;

    uint256 constant IC16x = 16736323514378618140939130318398850680332554462983631270505036048038935919413;
    uint256 constant IC16y = 15253913777072260212226473643583719027291252100227704060212389051827540166381;

    uint256 constant IC17x = 18529707877997203011864568455946519436060813816128807162010137333426987207854;
    uint256 constant IC17y = 16621110739854119947580732284282246073773457299863973913465912787748656345920;

    uint256 constant IC18x = 2441649412568037534690706284353649146698630867850330893485502108674901738500;
    uint256 constant IC18y = 3832967129583422305364814513641272219790010302337009923795885535324593675114;

    uint256 constant IC19x = 15061905841222015969067692241659629846680751419436422878621659061704790539250;
    uint256 constant IC19y = 5731781894266788506756897779453974442224780069901073403244917415345947798682;

    uint256 constant IC20x = 2103898256642184812781169340535569326993916016083808756079602987363258523288;
    uint256 constant IC20y = 5550741881589607429455004498084362224238526853652477137194079569202820117512;

    uint256 constant IC21x = 12796178601450272025275838118459215677533457191398460850378568607320611998923;
    uint256 constant IC21y = 2255512909136996511688805144916459449208460512499640557902582092271744798727;

    uint256 constant IC22x = 6319547752546597722190373013231157120231451900950791728622719804758335128960;
    uint256 constant IC22y = 13602864014754610248387368606588368830251825474198144931882666182102833147223;

    uint256 constant IC23x = 3470925779637863874072984914060020214241999558499339444846445007677401497675;
    uint256 constant IC23y = 8297113454044800714730170149569079070772931794764513196425613426883210519148;

    uint256 constant IC24x = 20039637522621293607238794426964523149708247648229211391980578033118003797901;
    uint256 constant IC24y = 485850878212691972105197784805992833181623175005139226924682376128850627899;

    uint256 constant IC25x = 16174913319742348283275842587039080909848988530286834617170927706721827116289;
    uint256 constant IC25y = 3172658347547878619170620845721502869522098511593257732439935344960713316747;

    uint256 constant IC26x = 12553096376771073193615690388108653459678447832215027394009101310630858383950;
    uint256 constant IC26y = 226498528693674234813921024532857233247270077112955561488045989302401265147;

    uint256 constant IC27x = 20847574726656061564387471788964712777296886127922747966254153066323858500424;
    uint256 constant IC27y = 21533502437588231400439633833520587353795661001918397851166850240382106768493;

    uint256 constant IC28x = 16081956006712459027841060861939075412372058239667461434264195438092633951314;
    uint256 constant IC28y = 11521362560670589415882741522629661594136469648772846690633545507663265337362;

    uint256 constant IC29x = 7314398963771375216946940647691087308696092934377952697344922851718273312026;
    uint256 constant IC29y = 1642525634273170102828993459896474718975894800859632726042956257189113605932;

    uint256 constant IC30x = 19900060200277629155298061979849909924058435159704589105772854708812133670503;
    uint256 constant IC30y = 20538534210754687516298412764784764512224853510744798304300678908767724608230;

    uint256 constant IC31x = 12237772473447860597380780705028993657080864919584185876290177570765934952043;
    uint256 constant IC31y = 5824869125799736158506242957470912432474946091965603340545555672654565065863;

    uint256 constant IC32x = 8380588932669366006912348437473403537699539850886266502499457471908143557408;
    uint256 constant IC32y = 15403527675884761432738338864573611562081100193497617364911509418163052357908;

    uint256 constant IC33x = 20677387936747383996903252652761772217450491946393626065106843336860051041787;
    uint256 constant IC33y = 2714176589499387639874107536725134586230882964660595307285248031407664510760;

    uint256 constant IC34x = 10322416116632416813808489655672766659352649585067280165064679670844511220097;
    uint256 constant IC34y = 15948795754630323030509312112177220520535333703059412863479349513482862382734;

    uint256 constant IC35x = 10287192433896353926182311294405797632454985350030613942724393903868236117376;
    uint256 constant IC35y = 17632311670956513429111209026719089321324573752354347844079791689989813562246;

    uint256 constant IC36x = 12259677231984266486343534843672555822740639723632818554459513231397331335147;
    uint256 constant IC36y = 962585112269661366130754284841240375656247122045819592367400826313646147843;

    uint256 constant IC37x = 10117611432118084899017130255712356464387606456871127249079338019597540784452;
    uint256 constant IC37y = 3846912152723494968296485940031567146490050281936924477309474534022863382819;

    uint256 constant IC38x = 9499705263385432687935906570704942159309694028821417922201076804378995724878;
    uint256 constant IC38y = 17710139096841516874667750730355344211525649215470768757213785616882085055920;

    uint256 constant IC39x = 5990963905005320950265708623634122060778940626998498005490888320379019875697;
    uint256 constant IC39y = 11511373442541936849323788999263978546833508812140155452835855589401586875944;

    uint256 constant IC40x = 10970649523130506689832296976458204202699415959471185506292658735261986500541;
    uint256 constant IC40y = 19483078629548770727110379524119313914388162430635649594689948789600064266434;

    uint256 constant IC41x = 8872651720655400131875430081414839479388145863656167227543473168208356247356;
    uint256 constant IC41y = 3521525927673436108298830162455408991672829936966253878644155995301516003315;

    uint256 constant IC42x = 12990116133627009078721472387377839043131333859690371974716430582430809888879;
    uint256 constant IC42y = 5200531009963083886489112390801659530057750700921381610290426345099913863658;

    uint256 constant IC43x = 14631057168054769725329641720532947202480900557733802715630503129346517678616;
    uint256 constant IC43y = 4789986692343225073553679067403732781056160439356880719585740995809258841675;

    uint256 constant IC44x = 453202482677903806737115420571357996554887269613945178304029694036317248021;
    uint256 constant IC44y = 18335757045225489598143336977949363456528498155805544794993877451969024111658;

    uint256 constant IC45x = 18889574204924657896132362148231695547851551557649719740964100713493894355345;
    uint256 constant IC45y = 5018243386767632706111832278337517555834464902085784111329615008670527799419;

    // Memory data
    uint16 constant pVk = 0;
    uint16 constant pPairing = 128;

    uint16 constant pLastMem = 896;

    function verifyProof(
        uint256[2] calldata _pA,
        uint256[2][2] calldata _pB,
        uint256[2] calldata _pC,
        uint256[45] calldata _pubSignals
    ) public view returns (bool) {
        assembly {
            function checkField(v) {
                if iszero(lt(v, r)) {
                    mstore(0, 0)
                    return(0, 0x20)
                }
            }

            // G1 function to multiply a G1 value(x,y) to value in an address
            function g1_mulAccC(pR, x, y, s) {
                let success
                let mIn := mload(0x40)
                mstore(mIn, x)
                mstore(add(mIn, 32), y)
                mstore(add(mIn, 64), s)

                success := staticcall(sub(gas(), 2000), 7, mIn, 96, mIn, 64)

                if iszero(success) {
                    mstore(0, 0)
                    return(0, 0x20)
                }

                mstore(add(mIn, 64), mload(pR))
                mstore(add(mIn, 96), mload(add(pR, 32)))

                success := staticcall(sub(gas(), 2000), 6, mIn, 128, pR, 64)

                if iszero(success) {
                    mstore(0, 0)
                    return(0, 0x20)
                }
            }

            function checkPairing(pA, pB, pC, pubSignals, pMem) -> isOk {
                let _pPairing := add(pMem, pPairing)
                let _pVk := add(pMem, pVk)

                mstore(_pVk, IC0x)
                mstore(add(_pVk, 32), IC0y)

                // Compute the linear combination vk_x

                g1_mulAccC(_pVk, IC1x, IC1y, calldataload(add(pubSignals, 0)))

                g1_mulAccC(_pVk, IC2x, IC2y, calldataload(add(pubSignals, 32)))

                g1_mulAccC(_pVk, IC3x, IC3y, calldataload(add(pubSignals, 64)))

                g1_mulAccC(_pVk, IC4x, IC4y, calldataload(add(pubSignals, 96)))

                g1_mulAccC(_pVk, IC5x, IC5y, calldataload(add(pubSignals, 128)))

                g1_mulAccC(_pVk, IC6x, IC6y, calldataload(add(pubSignals, 160)))

                g1_mulAccC(_pVk, IC7x, IC7y, calldataload(add(pubSignals, 192)))

                g1_mulAccC(_pVk, IC8x, IC8y, calldataload(add(pubSignals, 224)))

                g1_mulAccC(_pVk, IC9x, IC9y, calldataload(add(pubSignals, 256)))

                g1_mulAccC(_pVk, IC10x, IC10y, calldataload(add(pubSignals, 288)))

                g1_mulAccC(_pVk, IC11x, IC11y, calldataload(add(pubSignals, 320)))

                g1_mulAccC(_pVk, IC12x, IC12y, calldataload(add(pubSignals, 352)))

                g1_mulAccC(_pVk, IC13x, IC13y, calldataload(add(pubSignals, 384)))

                g1_mulAccC(_pVk, IC14x, IC14y, calldataload(add(pubSignals, 416)))

                g1_mulAccC(_pVk, IC15x, IC15y, calldataload(add(pubSignals, 448)))

                g1_mulAccC(_pVk, IC16x, IC16y, calldataload(add(pubSignals, 480)))

                g1_mulAccC(_pVk, IC17x, IC17y, calldataload(add(pubSignals, 512)))

                g1_mulAccC(_pVk, IC18x, IC18y, calldataload(add(pubSignals, 544)))

                g1_mulAccC(_pVk, IC19x, IC19y, calldataload(add(pubSignals, 576)))

                g1_mulAccC(_pVk, IC20x, IC20y, calldataload(add(pubSignals, 608)))

                g1_mulAccC(_pVk, IC21x, IC21y, calldataload(add(pubSignals, 640)))

                g1_mulAccC(_pVk, IC22x, IC22y, calldataload(add(pubSignals, 672)))

                g1_mulAccC(_pVk, IC23x, IC23y, calldataload(add(pubSignals, 704)))

                g1_mulAccC(_pVk, IC24x, IC24y, calldataload(add(pubSignals, 736)))

                g1_mulAccC(_pVk, IC25x, IC25y, calldataload(add(pubSignals, 768)))

                g1_mulAccC(_pVk, IC26x, IC26y, calldataload(add(pubSignals, 800)))

                g1_mulAccC(_pVk, IC27x, IC27y, calldataload(add(pubSignals, 832)))

                g1_mulAccC(_pVk, IC28x, IC28y, calldataload(add(pubSignals, 864)))

                g1_mulAccC(_pVk, IC29x, IC29y, calldataload(add(pubSignals, 896)))

                g1_mulAccC(_pVk, IC30x, IC30y, calldataload(add(pubSignals, 928)))

                g1_mulAccC(_pVk, IC31x, IC31y, calldataload(add(pubSignals, 960)))

                g1_mulAccC(_pVk, IC32x, IC32y, calldataload(add(pubSignals, 992)))

                g1_mulAccC(_pVk, IC33x, IC33y, calldataload(add(pubSignals, 1024)))

                g1_mulAccC(_pVk, IC34x, IC34y, calldataload(add(pubSignals, 1056)))

                g1_mulAccC(_pVk, IC35x, IC35y, calldataload(add(pubSignals, 1088)))

                g1_mulAccC(_pVk, IC36x, IC36y, calldataload(add(pubSignals, 1120)))

                g1_mulAccC(_pVk, IC37x, IC37y, calldataload(add(pubSignals, 1152)))

                g1_mulAccC(_pVk, IC38x, IC38y, calldataload(add(pubSignals, 1184)))

                g1_mulAccC(_pVk, IC39x, IC39y, calldataload(add(pubSignals, 1216)))

                g1_mulAccC(_pVk, IC40x, IC40y, calldataload(add(pubSignals, 1248)))

                g1_mulAccC(_pVk, IC41x, IC41y, calldataload(add(pubSignals, 1280)))

                g1_mulAccC(_pVk, IC42x, IC42y, calldataload(add(pubSignals, 1312)))

                g1_mulAccC(_pVk, IC43x, IC43y, calldataload(add(pubSignals, 1344)))

                g1_mulAccC(_pVk, IC44x, IC44y, calldataload(add(pubSignals, 1376)))

                g1_mulAccC(_pVk, IC45x, IC45y, calldataload(add(pubSignals, 1408)))

                // -A
                mstore(_pPairing, calldataload(pA))
                mstore(add(_pPairing, 32), mod(sub(q, calldataload(add(pA, 32))), q))

                // B
                mstore(add(_pPairing, 64), calldataload(pB))
                mstore(add(_pPairing, 96), calldataload(add(pB, 32)))
                mstore(add(_pPairing, 128), calldataload(add(pB, 64)))
                mstore(add(_pPairing, 160), calldataload(add(pB, 96)))

                // alpha1
                mstore(add(_pPairing, 192), alphax)
                mstore(add(_pPairing, 224), alphay)

                // beta2
                mstore(add(_pPairing, 256), betax1)
                mstore(add(_pPairing, 288), betax2)
                mstore(add(_pPairing, 320), betay1)
                mstore(add(_pPairing, 352), betay2)

                // vk_x
                mstore(add(_pPairing, 384), mload(add(pMem, pVk)))
                mstore(add(_pPairing, 416), mload(add(pMem, add(pVk, 32))))

                // gamma2
                mstore(add(_pPairing, 448), gammax1)
                mstore(add(_pPairing, 480), gammax2)
                mstore(add(_pPairing, 512), gammay1)
                mstore(add(_pPairing, 544), gammay2)

                // C
                mstore(add(_pPairing, 576), calldataload(pC))
                mstore(add(_pPairing, 608), calldataload(add(pC, 32)))

                // delta2
                mstore(add(_pPairing, 640), deltax1)
                mstore(add(_pPairing, 672), deltax2)
                mstore(add(_pPairing, 704), deltay1)
                mstore(add(_pPairing, 736), deltay2)

                let success := staticcall(sub(gas(), 2000), 8, _pPairing, 768, _pPairing, 0x20)

                isOk := and(success, mload(_pPairing))
            }

            let pMem := mload(0x40)
            mstore(0x40, add(pMem, pLastMem))

            // Validate that all evaluations ∈ F

            checkField(calldataload(add(_pubSignals, 0)))

            checkField(calldataload(add(_pubSignals, 32)))

            checkField(calldataload(add(_pubSignals, 64)))

            checkField(calldataload(add(_pubSignals, 96)))

            checkField(calldataload(add(_pubSignals, 128)))

            checkField(calldataload(add(_pubSignals, 160)))

            checkField(calldataload(add(_pubSignals, 192)))

            checkField(calldataload(add(_pubSignals, 224)))

            checkField(calldataload(add(_pubSignals, 256)))

            checkField(calldataload(add(_pubSignals, 288)))

            checkField(calldataload(add(_pubSignals, 320)))

            checkField(calldataload(add(_pubSignals, 352)))

            checkField(calldataload(add(_pubSignals, 384)))

            checkField(calldataload(add(_pubSignals, 416)))

            checkField(calldataload(add(_pubSignals, 448)))

            checkField(calldataload(add(_pubSignals, 480)))

            checkField(calldataload(add(_pubSignals, 512)))

            checkField(calldataload(add(_pubSignals, 544)))

            checkField(calldataload(add(_pubSignals, 576)))

            checkField(calldataload(add(_pubSignals, 608)))

            checkField(calldataload(add(_pubSignals, 640)))

            checkField(calldataload(add(_pubSignals, 672)))

            checkField(calldataload(add(_pubSignals, 704)))

            checkField(calldataload(add(_pubSignals, 736)))

            checkField(calldataload(add(_pubSignals, 768)))

            checkField(calldataload(add(_pubSignals, 800)))

            checkField(calldataload(add(_pubSignals, 832)))

            checkField(calldataload(add(_pubSignals, 864)))

            checkField(calldataload(add(_pubSignals, 896)))

            checkField(calldataload(add(_pubSignals, 928)))

            checkField(calldataload(add(_pubSignals, 960)))

            checkField(calldataload(add(_pubSignals, 992)))

            checkField(calldataload(add(_pubSignals, 1024)))

            checkField(calldataload(add(_pubSignals, 1056)))

            checkField(calldataload(add(_pubSignals, 1088)))

            checkField(calldataload(add(_pubSignals, 1120)))

            checkField(calldataload(add(_pubSignals, 1152)))

            checkField(calldataload(add(_pubSignals, 1184)))

            checkField(calldataload(add(_pubSignals, 1216)))

            checkField(calldataload(add(_pubSignals, 1248)))

            checkField(calldataload(add(_pubSignals, 1280)))

            checkField(calldataload(add(_pubSignals, 1312)))

            checkField(calldataload(add(_pubSignals, 1344)))

            checkField(calldataload(add(_pubSignals, 1376)))

            checkField(calldataload(add(_pubSignals, 1408)))

            checkField(calldataload(add(_pubSignals, 1440)))

            // Validate all evaluations
            let isValid := checkPairing(_pA, _pB, _pC, _pubSignals, pMem)

            mstore(0, isValid)
            return(0, 0x20)
        }
    }
}
