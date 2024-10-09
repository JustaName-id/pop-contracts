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

contract VerifierProveRSAPSS65537SHA256 {
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
    uint256 constant deltax1 = 17791717121536251520495464541057656653360884081910745435733690547414757895576;
    uint256 constant deltax2 = 5774841998113151043760261934488429843067837608341913161628827040114522871783;
    uint256 constant deltay1 = 10797641472479914849477152356738775084352111000375397928167172916002737888108;
    uint256 constant deltay2 = 10412593341296597336633658997624010135215901428971039121430393321093251486010;

    uint256 constant IC0x = 4684651268181398011726198207586064916563109424519799671447040554177761327581;
    uint256 constant IC0y = 5646480697979513364632655400640442231721279672151872370405611585019884667849;

    uint256 constant IC1x = 5266984804443932423599907060286990797035820630027860078713155742053491216164;
    uint256 constant IC1y = 14024907817288541220808288059373175708732251646300811664592881590475179120677;

    uint256 constant IC2x = 21705648339514119886198556067822664294569926497629773756760273440041982845574;
    uint256 constant IC2y = 3852335775353137512620502674789951389129806478764933750343477463158332028115;

    uint256 constant IC3x = 857694645829818224785238900659574910617545416017929078211767864699853475343;
    uint256 constant IC3y = 7724816551954034490246563920650001755176470805066514765240540816546570632363;

    uint256 constant IC4x = 8796138712170099621157811615112807279207104489250243127623812080867019717182;
    uint256 constant IC4y = 3845320051731248129908296852264316852416297949759060386208292623527647477322;

    uint256 constant IC5x = 9293194751075344209150417992082655781070100773845430131020742609801731606124;
    uint256 constant IC5y = 17726686469180827124886720388092823187044951022798204940643082679323395922309;

    uint256 constant IC6x = 16229690040114619596910353184315258315194786362682601216767299570551111821366;
    uint256 constant IC6y = 8796991544341206445057640396817016563985442272744731807018628966541986975915;

    uint256 constant IC7x = 11181875107442774734970184599542784452539102962378201912078426570576559076174;
    uint256 constant IC7y = 8933286924367825291170976737726157793343856399242385491015189091573807147379;

    uint256 constant IC8x = 963118605539008360308854653571054087280511878165433642461991886831459921552;
    uint256 constant IC8y = 15205950083283460953449351314362401174040299808887828785916204879315797916300;

    uint256 constant IC9x = 13693923761966807504144877963583322253174957278956253996015855079426646494485;
    uint256 constant IC9y = 16633981527118273333179938660703070731443433406847625078361472153809728594952;

    uint256 constant IC10x = 10741972559367960917512220245392444854516262611935817636034779504226247896966;
    uint256 constant IC10y = 13917810165411552288046896040670999455432212329327564490547340261280930349272;

    uint256 constant IC11x = 12020317655285291748772626052521392511665461334984897580241873819431784808082;
    uint256 constant IC11y = 10427627256220582060476829783152963058723846179135882661466746110228193097804;

    uint256 constant IC12x = 17622384785788906128135592629281039166968631578900481210240230148231071205782;
    uint256 constant IC12y = 2596040077892361255392147484357223304305531607852574899223981924643654950354;

    uint256 constant IC13x = 20566953064610197672746467834998103739169560131582435134829272243219075908257;
    uint256 constant IC13y = 12361581784431931822790641031468564708666014011047317610327208904372294251133;

    uint256 constant IC14x = 19952179263313976520595194172341941318593469145307534591022442547494924890761;
    uint256 constant IC14y = 20565652125335975932256311165466963011208642464478084854080430210894606432854;

    uint256 constant IC15x = 7987949163611957360472267511074337362324520980462850123157753640132905448294;
    uint256 constant IC15y = 12703639403103772792088256885585867293480768076589765738747767992799694636474;

    uint256 constant IC16x = 16815408691688241175902443259001152747302614512651167022186923975367940824174;
    uint256 constant IC16y = 5551098540810063383107013498127323450990889456604296162062652273044933192953;

    uint256 constant IC17x = 8428637878386231817013859468788345333360239442975722051924999192339074780385;
    uint256 constant IC17y = 2688824452266932844596415283187462802880566090468010757394646909662571347419;

    uint256 constant IC18x = 14600478317439944428638032722161178371307415253405204252624027413440628600404;
    uint256 constant IC18y = 16282739528429719481670138451929382405527323940725043406747231864617874222411;

    uint256 constant IC19x = 18789898397717243270872801776897706223472156645723370735104284531062965305218;
    uint256 constant IC19y = 11198860701038925024055623325054704598855166579511158374516162474607615775687;

    uint256 constant IC20x = 14556713419923301551382584124427717224859000554821226793711079893514562448732;
    uint256 constant IC20y = 5498632422837938164215697144698412639871124876079853790993620409224437829224;

    uint256 constant IC21x = 2541890622953518204259419820942364861460393296242309646107417139473467655247;
    uint256 constant IC21y = 941812073590298584187981482835537598097056081295360578696214302719972811545;

    uint256 constant IC22x = 5799930020592598737475572009283069713836825874927682852787991742658614219379;
    uint256 constant IC22y = 3914107556574287676888249408337616670576518766024291310356081009627031306950;

    uint256 constant IC23x = 8868810667600284529099398902795979904752930998053032592633419716897819106872;
    uint256 constant IC23y = 4814824973381481064146228879313361457063910327492691134167897087966896984487;

    uint256 constant IC24x = 17762364526596754421264133990590205916834553273792653052368506394616596286697;
    uint256 constant IC24y = 17592458823502762069423128222501793372117776127587499820012695829069509707168;

    uint256 constant IC25x = 16090479665797066707424411503224790903218673078234186600093857849690811439541;
    uint256 constant IC25y = 21849762646124384087181991049744485899463249734427139388974797255912630038007;

    uint256 constant IC26x = 20032249184250351952098477365509155530507083757686235306453328022572023626616;
    uint256 constant IC26y = 8208023752754094623923008130425972776321072718863009097832548898220276922650;

    uint256 constant IC27x = 19936633402627029316587528757123121900403741170102855007408897208297667320771;
    uint256 constant IC27y = 19114192326869516173362723223261670849584909985592744661314094692898738494810;

    uint256 constant IC28x = 3096561682375342680468913945359059083957131954720189953910713997868837352237;
    uint256 constant IC28y = 8500433602161983626069467934051902585890805551596256055910360981824134395559;

    uint256 constant IC29x = 9967891198140228439553319777926026697875175582050226774750017422438934613099;
    uint256 constant IC29y = 10784888094848944983184250635166043380664084293754186824003005587439062668001;

    uint256 constant IC30x = 12240169369265509805523022459904588036356694275372359386998750968711812920990;
    uint256 constant IC30y = 4263164530522971394960747652941892739959649773523925646663106594561099715793;

    uint256 constant IC31x = 4626451919943892810073286777881298275607361405733957856099035365686706225226;
    uint256 constant IC31y = 9337097953946763316287491696435329762797003240109401090740990426008156570470;

    uint256 constant IC32x = 1846895928808991842389963375582920501759339585257830305544496562714117264264;
    uint256 constant IC32y = 2463044897171676807197822422492676616183967169974309732144721536449132556969;

    uint256 constant IC33x = 13047721724901452663919429950068875019429955145140979178343211734278290856981;
    uint256 constant IC33y = 17552016306382209741752596370159479519757883571181186959089437430211205401501;

    uint256 constant IC34x = 21422991739272695762919332947243925154075700127406116086821631805919197812281;
    uint256 constant IC34y = 18605475190072211661740552782001120882668717741111105691134439046372453664622;

    uint256 constant IC35x = 2937006959585250672974445202974939011078244122574704559006710795766546227510;
    uint256 constant IC35y = 10727642126451334680914843758973657557500440200673865311520003034386056512710;

    uint256 constant IC36x = 1310268367797799190874800665710876252790056033597219644236149879640987417812;
    uint256 constant IC36y = 2896994521897329159654863693268450357393120531544488745545581454366820411553;

    uint256 constant IC37x = 7964647116782681424004522158839141004649062741066702441919082994572056947819;
    uint256 constant IC37y = 21188549956332183895394166393301562319662036207376817532946894104358590811387;

    uint256 constant IC38x = 16224215951709458344045423471605775308767456258288535719944776712661128187045;
    uint256 constant IC38y = 177534752442093696881574815043987031959557434775636803420289273794067312083;

    uint256 constant IC39x = 12565092777220050121169529421881010897170010177266560298380788002287075201106;
    uint256 constant IC39y = 15193931205439693658725124331951645777335923535563860782910967444995653859132;

    uint256 constant IC40x = 7725769424601889638494683783047011313958987684482999021553354366635448933190;
    uint256 constant IC40y = 8963051248794856689686379260846525218689818389725405268920444423263975057565;

    uint256 constant IC41x = 21081997519764456783610347474369480586900618364439686871055511228555251145828;
    uint256 constant IC41y = 17090341531491782655043505675981549939420503686354151353082819606400559261246;

    uint256 constant IC42x = 18863016003931219797838604765803467920178677606381680650875859662278877757918;
    uint256 constant IC42y = 14600268253426199664306917061040427147029564136024462994919554999576396997067;

    uint256 constant IC43x = 13402599505139003770935234027589542071313045331868087266355420545193310757522;
    uint256 constant IC43y = 6325814678974269940731806299551336785990669808334821350721054205142164737443;

    uint256 constant IC44x = 12123264485608457812983594791391685162237338964140869152259745645867395621138;
    uint256 constant IC44y = 2787022793695889393183076841942402840550777286447710839590763008881439621105;

    uint256 constant IC45x = 17906256060744778808434420800871490997323098376109399407145573887088209328340;
    uint256 constant IC45y = 15575133596558534346218399804513028828974354702366562487051272041219679291886;

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
