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

contract VerifierProveRSA65537SHA1 {
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
    uint256 constant deltax1 = 11167907892841666403957832356709520977293970158634866882392265166345265068363;
    uint256 constant deltax2 = 16872392223821572764936649764287784781718944131099315676209776095837569117904;
    uint256 constant deltay1 = 7205763782730227201846667395610645266636559758386923441626130457858150205593;
    uint256 constant deltay2 = 21431575462002591770323513073526746494975434587702590833550841061588079840688;

    uint256 constant IC0x = 5372146671465980857288451423793809619909428509419807288054761024072806425490;
    uint256 constant IC0y = 12507707583912320547867629488254742663263624728953540104953275308315599792266;

    uint256 constant IC1x = 13128368587403711033616720538514787971492577895133840365050402463264270362516;
    uint256 constant IC1y = 18152013960841164845501873266912377061458336470519091262434617532900267751206;

    uint256 constant IC2x = 10161101362142991751744748972131203202506125253721989744751420827892784650902;
    uint256 constant IC2y = 16951225941857055587451575654421020553007895398817554419713854816099128771581;

    uint256 constant IC3x = 5303715541915233475754837972709105455818794238031331671174794984501993701391;
    uint256 constant IC3y = 15581982216930637837308415576832193834703202355393079537603951057564224943131;

    uint256 constant IC4x = 2462863200020424318129030844530817237197676607260102610133318516001900400489;
    uint256 constant IC4y = 13097691651600502479454931629072365391193901755183094296941967355964514243636;

    uint256 constant IC5x = 14678627773104604478288530826826680530009332773369580592849246857992325561710;
    uint256 constant IC5y = 10365971920011004418240977119613757869610044295144973577358941347101994944433;

    uint256 constant IC6x = 7629169762380404058218883592278245650691339195154601410283320410387054800541;
    uint256 constant IC6y = 10660150767998384271623612259069399430269418438510552327117583218431765588509;

    uint256 constant IC7x = 17731494977248739001516192779221419517156025871509411227791291416806538403196;
    uint256 constant IC7y = 15497842569346739061566713809996449369303092236789727738601603334696435038620;

    uint256 constant IC8x = 5849425591153685284760700814449649054301072696052985473850266412190113455444;
    uint256 constant IC8y = 6788276574013673401190273149675752361890299567282430377629326543432673600065;

    uint256 constant IC9x = 9621445544297264153515494173159864048522408071589694846883253604607947517549;
    uint256 constant IC9y = 9372285298420651684965825178838351889369584794304064705975485053188635245477;

    uint256 constant IC10x = 5869081078958558639104869897966899601335095939711799176770195741372464222214;
    uint256 constant IC10y = 15608571681425101286283087913816884437251685941281262036785791582947679348274;

    uint256 constant IC11x = 12798186086987141987849208874619643635197944719535352921185487994648272400646;
    uint256 constant IC11y = 1730540945995748238194851194988480419779045757047663760157379732070332260364;

    uint256 constant IC12x = 11729385733964941942476034571891530867280538932369688508029203310057616923412;
    uint256 constant IC12y = 10150106093429898597232385496424270851264356901378214209053537320682817380435;

    uint256 constant IC13x = 5031236590092008883931044158507212145175348054169627395045336130741431893273;
    uint256 constant IC13y = 12257540082506663990297619879774254125901699148816705831786516723006097219484;

    uint256 constant IC14x = 4058858228144555538219189177650830763565940433982130494214258725574761723376;
    uint256 constant IC14y = 19645524203432948014883781104346736993901640430296566226262614692505026770028;

    uint256 constant IC15x = 6473382904859265129412305881388808495867723407016530274561495397549322502040;
    uint256 constant IC15y = 11996372806681637126232152485755435402917241719534202921572657719799151121523;

    uint256 constant IC16x = 10185073016811010071088471294502689011253819339569209141001819534748351508922;
    uint256 constant IC16y = 1255546678711053565085083377660659135992638828692919026029369266761866684689;

    uint256 constant IC17x = 2737444508998352733980779171111274764320221391281835378941057347176336598247;
    uint256 constant IC17y = 8374941612758196901618122156080083506970753750580782855302108677625097023913;

    uint256 constant IC18x = 11245329415771441237776004445860742471973131005815601854714329726008807508854;
    uint256 constant IC18y = 3619806315225989024625157394761386709683935193325890245025194234142747736093;

    uint256 constant IC19x = 18447454092373939061825324793174114204058763400100339992431679121909939107756;
    uint256 constant IC19y = 307334082740730179936687500685497454640915205006005638699965585245091699037;

    uint256 constant IC20x = 432675197171373227830848829350674770068574449760417341121935133595171450450;
    uint256 constant IC20y = 19305612733432227312380309209408584112011747785600566433871116976533993989129;

    uint256 constant IC21x = 5818673704085824243495464476117539061304887246695060519117342591642213611197;
    uint256 constant IC21y = 21556779886654312794017803997419966522115757404827071228267561705320120746743;

    uint256 constant IC22x = 20187566447356301429089789272773887881257539802982369665813466714535500748361;
    uint256 constant IC22y = 20172722903236608524699869891873816443765936899804030148153501112410047579069;

    uint256 constant IC23x = 14744972946457446478022566307995116553970726338447179789690691952764248865061;
    uint256 constant IC23y = 20232634999380585915453476346515032493263252001059640343576672696628993985514;

    uint256 constant IC24x = 11205965773623848124184450905180009874607993648006001357417586331278718144772;
    uint256 constant IC24y = 15467499680930437081565021575310431809484199082599110262589476553971426246712;

    uint256 constant IC25x = 5652112691206287654454355852624782434438712909264853450302903646669836341262;
    uint256 constant IC25y = 8211309538857019553262392353701243592521432131248686538623918204615450509410;

    uint256 constant IC26x = 2104631412080250914127444950483161473961896184657798039169868221202958783363;
    uint256 constant IC26y = 12533078423876030391825083070877519333694610656332659704695014677690364294791;

    uint256 constant IC27x = 1432565196463375086241351462787876355653962007148630702625463658487206240180;
    uint256 constant IC27y = 19572364759317661021745650657827336472337418019239669055371621917598291483056;

    uint256 constant IC28x = 7041696659034982342343197531718593141276138060388790562072005946042452062737;
    uint256 constant IC28y = 13214533139451062316684174067238920212216523508157677094805247772667291664798;

    uint256 constant IC29x = 4811004015181018494795169966765909232978377132625584258015337825979496276360;
    uint256 constant IC29y = 8068226007702623462255048196998157675787522374044578591572977528557663241580;

    uint256 constant IC30x = 6446155115052738528320389072901934825739791222898043627605802038865486825215;
    uint256 constant IC30y = 4056673003904409351312863774598900136876420956084767957038745567461124393536;

    uint256 constant IC31x = 2106437130432497009699020725958297734806257372353699708151359035724413025430;
    uint256 constant IC31y = 14520611226269665677419216841949787417862069376358431525526702484189657379289;

    uint256 constant IC32x = 19282627462742273667932115648200616663669119116054271287077622678551502282858;
    uint256 constant IC32y = 7457168485195841562979533164208076564811595667558785868686279093134486780062;

    uint256 constant IC33x = 14862331216049236060502979750411175287955863685238082775186897874037584732253;
    uint256 constant IC33y = 10335367618053674091672604037545280944966544395442315364691109324005279943141;

    uint256 constant IC34x = 1079230076711024227461224512340339487975410073179612563168643243183881011201;
    uint256 constant IC34y = 11663352424222607976172134824874195058194677130141301958972908901879848764681;

    uint256 constant IC35x = 11780292418046111992832524763983502042089961435545995538437776603424537117084;
    uint256 constant IC35y = 18297733663202076116132318120006093159823675841741592540332481377964677929016;

    uint256 constant IC36x = 19984872067866774932960021665424502749972793457927547844189654855075549738327;
    uint256 constant IC36y = 20137629500934585916887516188333193139064864900495800857336041200471597750153;

    uint256 constant IC37x = 13837690879292510597093628555608851280435393280242148657888166962878975165767;
    uint256 constant IC37y = 7480324580819329532072182749898501677241611153313578384276244558892084930829;

    uint256 constant IC38x = 11796233904126298210165007873842682534335775950532083632306926070658240980052;
    uint256 constant IC38y = 14589885794569143988176795064803638608652008824720956819772688738646653842843;

    uint256 constant IC39x = 19637230712308822556391350709912322563961356508389649672555792601501198809564;
    uint256 constant IC39y = 7632821211615438809756286841306802707225425025172116357664771120270246998319;

    uint256 constant IC40x = 5051175174006680480276829651596614062037167898925910279487416929731778188876;
    uint256 constant IC40y = 14648201796603683053804920522858540412970835484814202609990962897750413626365;

    uint256 constant IC41x = 11702005290347393712042660746831991369980153600939591258345265061733043551895;
    uint256 constant IC41y = 7580566967842047283237824567403464294914994946528950317353417364242424302471;

    uint256 constant IC42x = 2952787484637985983391610043608464190143897882228130657214455461518073817421;
    uint256 constant IC42y = 18467040067797656174869695934372694946230456679117776926737830040844238758120;

    uint256 constant IC43x = 3075438426675825054830108296186287846878981148515255809871551774459228904431;
    uint256 constant IC43y = 17196801286500487552376810537949766738344951352416219665362820931354586227206;

    uint256 constant IC44x = 17155005871262256500692082890538892343235562329116174488521865279408051854801;
    uint256 constant IC44y = 21696929628659795457341282361975092484777648507781923129403167889367197464407;

    uint256 constant IC45x = 4364937001931299957780125934777143748000579903771089754259364608029619109519;
    uint256 constant IC45y = 10302346693317599438562311882018770136784633392586325514383866776573714818976;

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
