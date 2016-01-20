/*
 * Copyright (c) 2015 The Decred developers
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package pgpwordlist

import (
	"strings"
)

// The wordlists to use.
var WordList = PGPWordList
var WordMap = pgpWordMap

// The PGP wordlist, as a slice.
var PGPWordList = strings.Split(pgpWordList, "\n")
var pgpWordList = `aardvark
adroitness
absurd
adviser
accrue
aftermath
acme
aggregate
adrift
alkali
adult
almighty
afflict
amulet
ahead
amusement
aimless
antenna
Algol
applicant
allow
Apollo
alone
armistice
ammo
article
ancient
asteroid
apple
Atlantic
artist
atmosphere
assume
autopsy
Athens
Babylon
atlas
backwater
Aztec
barbecue
baboon
belowground
backfield
bifocals
backward
bodyguard
banjo
bookseller
beaming
borderline
bedlamp
bottomless
beehive
Bradbury
beeswax
bravado
befriend
Brazilian
Belfast
breakaway
berserk
Burlington
billiard
businessman
bison
butterfat
blackjack
Camelot
blockade
candidate
blowtorch
cannonball
bluebird
Capricorn
bombast
caravan
bookshelf
caretaker
brackish
celebrate
breadline
cellulose
breakup
certify
brickyard
chambermaid
briefcase
Cherokee
Burbank
Chicago
button
clergyman
buzzard
coherence
cement
combustion
chairlift
commando
chatter
company
checkup
component
chisel
concurrent
choking
confidence
chopper
conformist
Christmas
congregate
clamshell
consensus
classic
consulting
classroom
corporate
cleanup
corrosion
clockwork
councilman
cobra
crossover
commence
crucifix
concert
cumbersome
cowbell
customer
crackdown
Dakota
cranky
decadence
crowfoot
December
crucial
decimal
crumpled
designing
crusade
detector
cubic
detergent
dashboard
determine
deadbolt
dictator
deckhand
dinosaur
dogsled
direction
dragnet
disable
drainage
disbelief
dreadful
disruptive
drifter
distortion
dropper
document
drumbeat
embezzle
drunken
enchanting
Dupont
enrollment
dwelling
enterprise
eating
equation
edict
equipment
egghead
escapade
eightball
Eskimo
endorse
everyday
endow
examine
enlist
existence
erase
exodus
escape
fascinate
exceed
filament
eyeglass
finicky
eyetooth
forever
facial
fortitude
fallout
frequency
flagpole
gadgetry
flatfoot
Galveston
flytrap
getaway
fracture
glossary
framework
gossamer
freedom
graduate
frighten
gravity
gazelle
guitarist
Geiger
hamburger
glitter
Hamilton
glucose
handiwork
goggles
hazardous
goldfish
headwaters
gremlin
hemisphere
guidance
hesitate
hamlet
hideaway
highchair
holiness
hockey
hurricane
indoors
hydraulic
indulge
impartial
inverse
impetus
involve
inception
island
indigo
jawbone
inertia
keyboard
infancy
kickoff
inferno
kiwi
informant
klaxon
insincere
locale
insurgent
lockup
integrate
merit
intention
minnow
inventive
miser
Istanbul
Mohawk
Jamaica
mural
Jupiter
music
leprosy
necklace
letterhead
Neptune
liberty
newborn
maritime
nightbird
matchmaker
Oakland
maverick
obtuse
Medusa
offload
megaton
optic
microscope
orca
microwave
payday
midsummer
peachy
millionaire
pheasant
miracle
physique
misnomer
playhouse
molasses
Pluto
molecule
preclude
Montana
prefer
monument
preshrunk
mosquito
printer
narrative
prowler
nebula
pupil
newsletter
puppy
Norwegian
python
October
quadrant
Ohio
quiver
onlooker
quota
opulent
ragtime
Orlando
ratchet
outfielder
rebirth
Pacific
reform
pandemic
regain
Pandora
reindeer
paperweight
rematch
paragon
repay
paragraph
retouch
paramount
revenge
passenger
reward
pedigree
rhythm
Pegasus
ribcage
penetrate
ringbolt
perceptive
robust
performance
rocker
pharmacy
ruffled
phonetic
sailboat
photograph
sawdust
pioneer
scallion
pocketful
scenic
politeness
scorecard
positive
Scotland
potato
seabird
processor
select
provincial
sentence
proximate
shadow
puberty
shamrock
publisher
showgirl
pyramid
skullcap
quantity
skydive
racketeer
slingshot
rebellion
slowdown
recipe
snapline
recover
snapshot
repellent
snowcap
replica
snowslide
reproduce
solo
resistor
southward
responsive
soybean
retraction
spaniel
retrieval
spearhead
retrospect
spellbind
revenue
spheroid
revival
spigot
revolver
spindle
sandalwood
spyglass
sardonic
stagehand
Saturday
stagnate
savagery
stairway
scavenger
standard
sensation
stapler
sociable
steamship
souvenir
sterling
specialist
stockman
speculate
stopwatch
stethoscope
stormy
stupendous
sugar
supportive
surmount
surrender
suspense
suspicious
sweatband
sympathy
swelter
tambourine
tactics
telephone
talon
therapist
tapeworm
tobacco
tempest
tolerance
tiger
tomorrow
tissue
torpedo
tonic
tradition
topmost
travesty
tracker
trombonist
transit
truncated
trauma
typewriter
treadmill
ultimate
Trojan
undaunted
trouble
underfoot
tumor
unicorn
tunnel
unify
tycoon
universe
uncut
unravel
unearth
upcoming
unwind
vacancy
uproot
vagabond
upset
vertigo
upshot
Virginia
vapor
visitor
village
vocalist
virus
voyager
Vulcan
warranty
waffle
Waterloo
wallet
whimsical
watchword
Wichita
wayside
Wilmington
willow
Wyoming
woodlark
yesteryear
Zulu
Yucatan`

// The PGP wordlist, as a map of string --> uint16.
// Notably, this map is stripped of case for string
// identification.
var pgpWordMap = map[string]uint16{
	"aardvark":    0,
	"adroitness":  1,
	"absurd":      2,
	"adviser":     3,
	"accrue":      4,
	"aftermath":   5,
	"acme":        6,
	"aggregate":   7,
	"adrift":      8,
	"alkali":      9,
	"adult":       10,
	"almighty":    11,
	"afflict":     12,
	"amulet":      13,
	"ahead":       14,
	"amusement":   15,
	"aimless":     16,
	"antenna":     17,
	"algol":       18,
	"applicant":   19,
	"allow":       20,
	"apollo":      21,
	"alone":       22,
	"armistice":   23,
	"ammo":        24,
	"article":     25,
	"ancient":     26,
	"asteroid":    27,
	"apple":       28,
	"atlantic":    29,
	"artist":      30,
	"atmosphere":  31,
	"assume":      32,
	"autopsy":     33,
	"athens":      34,
	"babylon":     35,
	"atlas":       36,
	"backwater":   37,
	"aztec":       38,
	"barbecue":    39,
	"baboon":      40,
	"belowground": 41,
	"backfield":   42,
	"bifocals":    43,
	"backward":    44,
	"bodyguard":   45,
	"banjo":       46,
	"bookseller":  47,
	"beaming":     48,
	"borderline":  49,
	"bedlamp":     50,
	"bottomless":  51,
	"beehive":     52,
	"bradbury":    53,
	"beeswax":     54,
	"bravado":     55,
	"befriend":    56,
	"brazilian":   57,
	"belfast":     58,
	"breakaway":   59,
	"berserk":     60,
	"burlington":  61,
	"billiard":    62,
	"businessman": 63,
	"bison":       64,
	"butterfat":   65,
	"blackjack":   66,
	"camelot":     67,
	"blockade":    68,
	"candidate":   69,
	"blowtorch":   70,
	"cannonball":  71,
	"bluebird":    72,
	"capricorn":   73,
	"bombast":     74,
	"caravan":     75,
	"bookshelf":   76,
	"caretaker":   77,
	"brackish":    78,
	"celebrate":   79,
	"breadline":   80,
	"cellulose":   81,
	"breakup":     82,
	"certify":     83,
	"brickyard":   84,
	"chambermaid": 85,
	"briefcase":   86,
	"cherokee":    87,
	"burbank":     88,
	"chicago":     89,
	"button":      90,
	"clergyman":   91,
	"buzzard":     92,
	"coherence":   93,
	"cement":      94,
	"combustion":  95,
	"chairlift":   96,
	"commando":    97,
	"chatter":     98,
	"company":     99,
	"checkup":     100,
	"component":   101,
	"chisel":      102,
	"concurrent":  103,
	"choking":     104,
	"confidence":  105,
	"chopper":     106,
	"conformist":  107,
	"christmas":   108,
	"congregate":  109,
	"clamshell":   110,
	"consensus":   111,
	"classic":     112,
	"consulting":  113,
	"classroom":   114,
	"corporate":   115,
	"cleanup":     116,
	"corrosion":   117,
	"clockwork":   118,
	"councilman":  119,
	"cobra":       120,
	"crossover":   121,
	"commence":    122,
	"crucifix":    123,
	"concert":     124,
	"cumbersome":  125,
	"cowbell":     126,
	"customer":    127,
	"crackdown":   128,
	"dakota":      129,
	"cranky":      130,
	"decadence":   131,
	"crowfoot":    132,
	"december":    133,
	"crucial":     134,
	"decimal":     135,
	"crumpled":    136,
	"designing":   137,
	"crusade":     138,
	"detector":    139,
	"cubic":       140,
	"detergent":   141,
	"dashboard":   142,
	"determine":   143,
	"deadbolt":    144,
	"dictator":    145,
	"deckhand":    146,
	"dinosaur":    147,
	"dogsled":     148,
	"direction":   149,
	"dragnet":     150,
	"disable":     151,
	"drainage":    152,
	"disbelief":   153,
	"dreadful":    154,
	"disruptive":  155,
	"drifter":     156,
	"distortion":  157,
	"dropper":     158,
	"document":    159,
	"drumbeat":    160,
	"embezzle":    161,
	"drunken":     162,
	"enchanting":  163,
	"dupont":      164,
	"enrollment":  165,
	"dwelling":    166,
	"enterprise":  167,
	"eating":      168,
	"equation":    169,
	"edict":       170,
	"equipment":   171,
	"egghead":     172,
	"escapade":    173,
	"eightball":   174,
	"eskimo":      175,
	"endorse":     176,
	"everyday":    177,
	"endow":       178,
	"examine":     179,
	"enlist":      180,
	"existence":   181,
	"erase":       182,
	"exodus":      183,
	"escape":      184,
	"fascinate":   185,
	"exceed":      186,
	"filament":    187,
	"eyeglass":    188,
	"finicky":     189,
	"eyetooth":    190,
	"forever":     191,
	"facial":      192,
	"fortitude":   193,
	"fallout":     194,
	"frequency":   195,
	"flagpole":    196,
	"gadgetry":    197,
	"flatfoot":    198,
	"galveston":   199,
	"flytrap":     200,
	"getaway":     201,
	"fracture":    202,
	"glossary":    203,
	"framework":   204,
	"gossamer":    205,
	"freedom":     206,
	"graduate":    207,
	"frighten":    208,
	"gravity":     209,
	"gazelle":     210,
	"guitarist":   211,
	"geiger":      212,
	"hamburger":   213,
	"glitter":     214,
	"hamilton":    215,
	"glucose":     216,
	"handiwork":   217,
	"goggles":     218,
	"hazardous":   219,
	"goldfish":    220,
	"headwaters":  221,
	"gremlin":     222,
	"hemisphere":  223,
	"guidance":    224,
	"hesitate":    225,
	"hamlet":      226,
	"hideaway":    227,
	"highchair":   228,
	"holiness":    229,
	"hockey":      230,
	"hurricane":   231,
	"indoors":     232,
	"hydraulic":   233,
	"indulge":     234,
	"impartial":   235,
	"inverse":     236,
	"impetus":     237,
	"involve":     238,
	"inception":   239,
	"island":      240,
	"indigo":      241,
	"jawbone":     242,
	"inertia":     243,
	"keyboard":    244,
	"infancy":     245,
	"kickoff":     246,
	"inferno":     247,
	"kiwi":        248,
	"informant":   249,
	"klaxon":      250,
	"insincere":   251,
	"locale":      252,
	"insurgent":   253,
	"lockup":      254,
	"integrate":   255,
	"merit":       256,
	"intention":   257,
	"minnow":      258,
	"inventive":   259,
	"miser":       260,
	"istanbul":    261,
	"mohawk":      262,
	"jamaica":     263,
	"mural":       264,
	"jupiter":     265,
	"music":       266,
	"leprosy":     267,
	"necklace":    268,
	"letterhead":  269,
	"neptune":     270,
	"liberty":     271,
	"newborn":     272,
	"maritime":    273,
	"nightbird":   274,
	"matchmaker":  275,
	"oakland":     276,
	"maverick":    277,
	"obtuse":      278,
	"medusa":      279,
	"offload":     280,
	"megaton":     281,
	"optic":       282,
	"microscope":  283,
	"orca":        284,
	"microwave":   285,
	"payday":      286,
	"midsummer":   287,
	"peachy":      288,
	"millionaire": 289,
	"pheasant":    290,
	"miracle":     291,
	"physique":    292,
	"misnomer":    293,
	"playhouse":   294,
	"molasses":    295,
	"pluto":       296,
	"molecule":    297,
	"preclude":    298,
	"montana":     299,
	"prefer":      300,
	"monument":    301,
	"preshrunk":   302,
	"mosquito":    303,
	"printer":     304,
	"narrative":   305,
	"prowler":     306,
	"nebula":      307,
	"pupil":       308,
	"newsletter":  309,
	"puppy":       310,
	"norwegian":   311,
	"python":      312,
	"october":     313,
	"quadrant":    314,
	"ohio":        315,
	"quiver":      316,
	"onlooker":    317,
	"quota":       318,
	"opulent":     319,
	"ragtime":     320,
	"orlando":     321,
	"ratchet":     322,
	"outfielder":  323,
	"rebirth":     324,
	"pacific":     325,
	"reform":      326,
	"pandemic":    327,
	"regain":      328,
	"pandora":     329,
	"reindeer":    330,
	"paperweight": 331,
	"rematch":     332,
	"paragon":     333,
	"repay":       334,
	"paragraph":   335,
	"retouch":     336,
	"paramount":   337,
	"revenge":     338,
	"passenger":   339,
	"reward":      340,
	"pedigree":    341,
	"rhythm":      342,
	"pegasus":     343,
	"ribcage":     344,
	"penetrate":   345,
	"ringbolt":    346,
	"perceptive":  347,
	"robust":      348,
	"performance": 349,
	"rocker":      350,
	"pharmacy":    351,
	"ruffled":     352,
	"phonetic":    353,
	"sailboat":    354,
	"photograph":  355,
	"sawdust":     356,
	"pioneer":     357,
	"scallion":    358,
	"pocketful":   359,
	"scenic":      360,
	"politeness":  361,
	"scorecard":   362,
	"positive":    363,
	"scotland":    364,
	"potato":      365,
	"seabird":     366,
	"processor":   367,
	"select":      368,
	"provincial":  369,
	"sentence":    370,
	"proximate":   371,
	"shadow":      372,
	"puberty":     373,
	"shamrock":    374,
	"publisher":   375,
	"showgirl":    376,
	"pyramid":     377,
	"skullcap":    378,
	"quantity":    379,
	"skydive":     380,
	"racketeer":   381,
	"slingshot":   382,
	"rebellion":   383,
	"slowdown":    384,
	"recipe":      385,
	"snapline":    386,
	"recover":     387,
	"snapshot":    388,
	"repellent":   389,
	"snowcap":     390,
	"replica":     391,
	"snowslide":   392,
	"reproduce":   393,
	"solo":        394,
	"resistor":    395,
	"southward":   396,
	"responsive":  397,
	"soybean":     398,
	"retraction":  399,
	"spaniel":     400,
	"retrieval":   401,
	"spearhead":   402,
	"retrospect":  403,
	"spellbind":   404,
	"revenue":     405,
	"spheroid":    406,
	"revival":     407,
	"spigot":      408,
	"revolver":    409,
	"spindle":     410,
	"sandalwood":  411,
	"spyglass":    412,
	"sardonic":    413,
	"stagehand":   414,
	"saturday":    415,
	"stagnate":    416,
	"savagery":    417,
	"stairway":    418,
	"scavenger":   419,
	"standard":    420,
	"sensation":   421,
	"stapler":     422,
	"sociable":    423,
	"steamship":   424,
	"souvenir":    425,
	"sterling":    426,
	"specialist":  427,
	"stockman":    428,
	"speculate":   429,
	"stopwatch":   430,
	"stethoscope": 431,
	"stormy":      432,
	"stupendous":  433,
	"sugar":       434,
	"supportive":  435,
	"surmount":    436,
	"surrender":   437,
	"suspense":    438,
	"suspicious":  439,
	"sweatband":   440,
	"sympathy":    441,
	"swelter":     442,
	"tambourine":  443,
	"tactics":     444,
	"telephone":   445,
	"talon":       446,
	"therapist":   447,
	"tapeworm":    448,
	"tobacco":     449,
	"tempest":     450,
	"tolerance":   451,
	"tiger":       452,
	"tomorrow":    453,
	"tissue":      454,
	"torpedo":     455,
	"tonic":       456,
	"tradition":   457,
	"topmost":     458,
	"travesty":    459,
	"tracker":     460,
	"trombonist":  461,
	"transit":     462,
	"truncated":   463,
	"trauma":      464,
	"typewriter":  465,
	"treadmill":   466,
	"ultimate":    467,
	"trojan":      468,
	"undaunted":   469,
	"trouble":     470,
	"underfoot":   471,
	"tumor":       472,
	"unicorn":     473,
	"tunnel":      474,
	"unify":       475,
	"tycoon":      476,
	"universe":    477,
	"uncut":       478,
	"unravel":     479,
	"unearth":     480,
	"upcoming":    481,
	"unwind":      482,
	"vacancy":     483,
	"uproot":      484,
	"vagabond":    485,
	"upset":       486,
	"vertigo":     487,
	"upshot":      488,
	"virginia":    489,
	"vapor":       490,
	"visitor":     491,
	"village":     492,
	"vocalist":    493,
	"virus":       494,
	"voyager":     495,
	"vulcan":      496,
	"warranty":    497,
	"waffle":      498,
	"waterloo":    499,
	"wallet":      500,
	"whimsical":   501,
	"watchword":   502,
	"wichita":     503,
	"wayside":     504,
	"wilmington":  505,
	"willow":      506,
	"wyoming":     507,
	"woodlark":    508,
	"yesteryear":  509,
	"zulu":        510,
	"yucatan":     511,
}
