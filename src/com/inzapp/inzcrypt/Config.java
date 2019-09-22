package com.inzapp.inzcrypt;

class Config {
    static final String KEY = "KEY_QUVTX0tFWV8xOTIzODczODkzODc0";
    static final long BIT_CONVERSION_KEY = 200823992740002938L;
    static final String AES_128 = "AES_128";
    static final String AES_256 = "AES_256";
    static final String DES = "DES";
    static final String PRIVATE_MAP_1 = "PRIVATE_MAP_1";
    static final String PRIVATE_MAP_2 = "PRIVATE_MAP_2";
    static final String PRIVATE_MAP_3 = "PRIVATE_MAP_3";
    static final String BIT_CONVERSION = "BIT_CONVERSION";
    static final String BASE_64 = "BASE_64";
    static final String CAESAR_64 = "CAESAR_64";
    static final String REVERSE = "REVERSE";

    static final String[] ENCRYPT_LAYER = new String[]{
            PRIVATE_MAP_1,
            PRIVATE_MAP_2,
            PRIVATE_MAP_3
    };

    static final byte[][] map1 = new byte[][]{
            {-128, 27},
            {-127, 23},
            {-126, -95},
            {-125, 33},
            {-124, 25},
            {-123, -35},
            {-122, 40},
            {-121, 119},
            {-120, 116},
            {-119, -18},
            {-118, -97},
            {-117, -86},
            {-116, -46},
            {-115, -115},
            {-114, 1},
            {-113, 3},
            {-112, -68},
            {-111, 37},
            {-110, 20},
            {-109, 43},
            {-108, 42},
            {-107, -118},
            {-106, -79},
            {-105, 84},
            {-104, -87},
            {-103, 97},
            {-102, -33},
            {-101, 91},
            {-100, -108},
            {-99, -70},
            {-98, 105},
            {-97, -43},
            {-96, -17},
            {-95, -105},
            {-94, -34},
            {-93, -53},
            {-92, 60},
            {-91, -85},
            {-90, -63},
            {-89, -89},
            {-88, -114},
            {-87, 112},
            {-86, -90},
            {-85, -93},
            {-84, 123},
            {-83, 104},
            {-82, 99},
            {-81, -8},
            {-80, 64},
            {-79, 55},
            {-78, 35},
            {-77, 11},
            {-76, 7},
            {-75, 6},
            {-74, 127},
            {-73, 13},
            {-72, 74},
            {-71, -98},
            {-70, 98},
            {-69, 124},
            {-68, -36},
            {-67, 65},
            {-66, 59},
            {-65, 46},
            {-64, 87},
            {-63, -119},
            {-62, -81},
            {-61, 56},
            {-60, 15},
            {-59, -112},
            {-58, 21},
            {-57, 73},
            {-56, 5},
            {-55, -28},
            {-54, 110},
            {-53, 24},
            {-52, 18},
            {-51, -41},
            {-50, 39},
            {-49, 89},
            {-48, 29},
            {-47, -22},
            {-46, -100},
            {-45, -3},
            {-44, -15},
            {-43, 9},
            {-42, -128},
            {-41, 16},
            {-40, -99},
            {-39, 47},
            {-38, -69},
            {-37, 92},
            {-36, 79},
            {-35, -57},
            {-34, -14},
            {-33, 22},
            {-32, -38},
            {-31, -92},
            {-30, -49},
            {-29, 62},
            {-28, 77},
            {-27, -67},
            {-26, -125},
            {-25, -40},
            {-24, -44},
            {-23, -23},
            {-22, -20},
            {-21, 113},
            {-20, -21},
            {-19, -126},
            {-18, 118},
            {-17, -52},
            {-16, 51},
            {-15, 28},
            {-14, 70},
            {-13, -65},
            {-12, -12},
            {-11, 95},
            {-10, 32},
            {-9, 121},
            {-8, -30},
            {-7, 45},
            {-6, -50},
            {-5, -5},
            {-4, -75},
            {-3, 17},
            {-2, 80},
            {-1, -1},
            {0, 78},
            {1, -2},
            {2, -110},
            {3, -54},
            {4, -48},
            {5, -60},
            {6, -76},
            {7, -47},
            {8, 2},
            {9, -51},
            {10, 107},
            {11, 90},
            {12, 36},
            {13, -32},
            {14, -103},
            {15, -123},
            {16, 83},
            {17, 120},
            {18, -124},
            {19, 19},
            {20, 54},
            {21, 75},
            {22, -24},
            {23, -80},
            {24, 101},
            {25, -78},
            {26, -26},
            {27, 66},
            {28, 111},
            {29, -6},
            {30, -19},
            {31, -74},
            {32, -59},
            {33, 69},
            {34, 93},
            {35, -11},
            {36, 76},
            {37, -120},
            {38, 4},
            {39, 57},
            {40, -84},
            {41, 52},
            {42, -55},
            {43, 49},
            {44, -127},
            {45, 38},
            {46, -7},
            {47, 114},
            {48, -113},
            {49, -82},
            {50, 14},
            {51, 53},
            {52, -122},
            {53, 50},
            {54, -71},
            {55, -111},
            {56, 61},
            {57, 10},
            {58, 103},
            {59, -101},
            {60, 88},
            {61, 8},
            {62, -116},
            {63, 41},
            {64, -45},
            {65, -13},
            {66, -62},
            {67, -42},
            {68, 117},
            {69, -39},
            {70, 126},
            {71, -117},
            {72, 102},
            {73, -16},
            {74, -27},
            {75, -83},
            {76, 106},
            {77, 86},
            {78, 85},
            {79, 72},
            {80, 96},
            {81, 0},
            {82, -37},
            {83, 30},
            {84, 48},
            {85, -96},
            {86, -56},
            {87, -61},
            {88, -9},
            {89, 34},
            {90, -88},
            {91, -109},
            {92, 31},
            {93, -29},
            {94, -4},
            {95, 82},
            {96, 71},
            {97, -104},
            {98, -102},
            {99, -121},
            {100, 26},
            {101, -66},
            {102, -72},
            {103, 58},
            {104, 68},
            {105, 94},
            {106, 115},
            {107, 100},
            {108, -25},
            {109, 67},
            {110, 122},
            {111, 44},
            {112, 125},
            {113, -91},
            {114, 63},
            {115, -94},
            {116, 109},
            {117, -31},
            {118, 81},
            {119, -64},
            {120, 108},
            {121, -58},
            {122, 12},
            {123, -107},
            {124, -106},
            {125, -73},
            {126, -10},
            {127, -77}
    };

    static final byte[][] map2 = new byte[][]{
            {-128, -89},
            {-127, -58},
            {-126, 109},
            {-125, -80},
            {-124, 81},
            {-123, -123},
            {-122, 116},
            {-121, 61},
            {-120, -82},
            {-119, -119},
            {-118, 21},
            {-117, 52},
            {-116, 46},
            {-115, -50},
            {-114, 97},
            {-113, 86},
            {-112, -4},
            {-111, 123},
            {-110, 55},
            {-109, -61},
            {-108, -70},
            {-107, 111},
            {-106, -103},
            {-105, -68},
            {-104, 88},
            {-103, -62},
            {-102, -77},
            {-101, 6},
            {-100, -63},
            {-99, -79},
            {-98, 23},
            {-97, 40},
            {-96, -115},
            {-95, 38},
            {-94, 28},
            {-93, 18},
            {-92, 64},
            {-91, -76},
            {-90, -75},
            {-89, -51},
            {-88, 49},
            {-87, 31},
            {-86, 105},
            {-85, -60},
            {-84, -38},
            {-83, 59},
            {-82, -37},
            {-81, -47},
            {-80, 79},
            {-79, 10},
            {-78, 24},
            {-77, 54},
            {-76, 91},
            {-75, -44},
            {-74, -43},
            {-73, -19},
            {-72, 51},
            {-71, -122},
            {-70, 115},
            {-69, -31},
            {-68, 100},
            {-67, -124},
            {-66, -22},
            {-65, 110},
            {-64, -64},
            {-63, 20},
            {-62, 96},
            {-61, 62},
            {-60, -111},
            {-59, -54},
            {-58, 26},
            {-57, -28},
            {-56, 29},
            {-55, 87},
            {-54, 122},
            {-53, -53},
            {-52, -10},
            {-51, -112},
            {-50, 53},
            {-49, 69},
            {-48, 72},
            {-47, 63},
            {-46, 126},
            {-45, 118},
            {-44, -56},
            {-43, -57},
            {-42, 90},
            {-41, 43},
            {-40, -59},
            {-39, 127},
            {-38, -121},
            {-37, 82},
            {-36, -105},
            {-35, 117},
            {-34, 125},
            {-33, 3},
            {-32, 58},
            {-31, -94},
            {-30, -1},
            {-29, 119},
            {-28, 121},
            {-27, -13},
            {-26, 68},
            {-25, -23},
            {-24, -32},
            {-23, 75},
            {-22, 25},
            {-21, 93},
            {-20, 15},
            {-19, -9},
            {-18, -3},
            {-17, -65},
            {-16, -8},
            {-15, -17},
            {-14, 34},
            {-13, -73},
            {-12, 102},
            {-11, -40},
            {-10, -116},
            {-9, 41},
            {-8, -104},
            {-7, -71},
            {-6, 65},
            {-5, -118},
            {-4, -100},
            {-3, 101},
            {-2, 17},
            {-1, -24},
            {0, -42},
            {1, 1},
            {2, -11},
            {3, 106},
            {4, 42},
            {5, 35},
            {6, -30},
            {7, 84},
            {8, 89},
            {9, -120},
            {10, 0},
            {11, -48},
            {12, 13},
            {13, -84},
            {14, -66},
            {15, 16},
            {16, -52},
            {17, 107},
            {18, 76},
            {19, -18},
            {20, 83},
            {21, -92},
            {22, -12},
            {23, -49},
            {24, 113},
            {25, -106},
            {26, -98},
            {27, 27},
            {28, 2},
            {29, 94},
            {30, 45},
            {31, -83},
            {32, -81},
            {33, 11},
            {34, 32},
            {35, -125},
            {36, 124},
            {37, -20},
            {38, -26},
            {39, 66},
            {40, -85},
            {41, -27},
            {42, 104},
            {43, -113},
            {44, -90},
            {45, -86},
            {46, 14},
            {47, 56},
            {48, -96},
            {49, 5},
            {50, 37},
            {51, -107},
            {52, -102},
            {53, -2},
            {54, -7},
            {55, 9},
            {56, -97},
            {57, 67},
            {58, -34},
            {59, -114},
            {60, 12},
            {61, -69},
            {62, 44},
            {63, -33},
            {64, -110},
            {65, -109},
            {66, -46},
            {67, 77},
            {68, 36},
            {69, -25},
            {70, -41},
            {71, -5},
            {72, 7},
            {73, 73},
            {74, -127},
            {75, 80},
            {76, -78},
            {77, 8},
            {78, 50},
            {79, -128},
            {80, -88},
            {81, -21},
            {82, -74},
            {83, -87},
            {84, -35},
            {85, -91},
            {86, -126},
            {87, 30},
            {88, 92},
            {89, -29},
            {90, -15},
            {91, -67},
            {92, 70},
            {93, -36},
            {94, 22},
            {95, 19},
            {96, 47},
            {97, 60},
            {98, -101},
            {99, 99},
            {100, 57},
            {101, 39},
            {102, 71},
            {103, 74},
            {104, -108},
            {105, -72},
            {106, -16},
            {107, 112},
            {108, 98},
            {109, 85},
            {110, 4},
            {111, 108},
            {112, -95},
            {113, -117},
            {114, 114},
            {115, 78},
            {116, 48},
            {117, 120},
            {118, -45},
            {119, -6},
            {120, -99},
            {121, -93},
            {122, -39},
            {123, -14},
            {124, 103},
            {125, -55},
            {126, 95},
            {127, 33}
    };

    static final byte[][] map3 = new byte[][]{
            {-128, -5},
            {-127, 38},
            {-126, 46},
            {-125, 1},
            {-124, 44},
            {-123, -18},
            {-122, 126},
            {-121, 107},
            {-120, -37},
            {-119, -117},
            {-118, -77},
            {-117, -115},
            {-116, 94},
            {-115, 13},
            {-114, -33},
            {-113, -73},
            {-112, -95},
            {-111, 31},
            {-110, -57},
            {-109, -45},
            {-108, -93},
            {-107, -47},
            {-106, 4},
            {-105, -28},
            {-104, 65},
            {-103, 56},
            {-102, 101},
            {-101, -1},
            {-100, 78},
            {-99, 39},
            {-98, 76},
            {-97, 127},
            {-96, -59},
            {-95, 33},
            {-94, 97},
            {-93, -2},
            {-92, -39},
            {-91, 109},
            {-90, 99},
            {-89, -46},
            {-88, 59},
            {-87, -19},
            {-86, 42},
            {-85, -16},
            {-84, 54},
            {-83, 72},
            {-82, 69},
            {-81, -109},
            {-80, -52},
            {-79, 35},
            {-78, 16},
            {-77, -60},
            {-76, -71},
            {-75, -107},
            {-74, -26},
            {-73, -30},
            {-72, 57},
            {-71, -100},
            {-70, -66},
            {-69, 22},
            {-68, 100},
            {-67, -90},
            {-66, 9},
            {-65, -86},
            {-64, 103},
            {-63, -83},
            {-62, -48},
            {-61, -8},
            {-60, 83},
            {-59, 45},
            {-58, 91},
            {-57, 7},
            {-56, -38},
            {-55, 73},
            {-54, 113},
            {-53, 63},
            {-52, -11},
            {-51, -40},
            {-50, -32},
            {-49, 114},
            {-48, 67},
            {-47, -13},
            {-46, -44},
            {-45, -123},
            {-44, -114},
            {-43, -4},
            {-42, 14},
            {-41, -69},
            {-40, -120},
            {-39, 53},
            {-38, 79},
            {-37, 108},
            {-36, 11},
            {-35, -118},
            {-34, 55},
            {-33, 125},
            {-32, -75},
            {-31, -42},
            {-30, -58},
            {-29, -56},
            {-28, -113},
            {-27, 68},
            {-26, 111},
            {-25, 58},
            {-24, 20},
            {-23, -23},
            {-22, -122},
            {-21, -34},
            {-20, -54},
            {-19, -99},
            {-18, -21},
            {-17, 10},
            {-16, -94},
            {-15, 64},
            {-14, 87},
            {-13, 18},
            {-12, 43},
            {-11, -82},
            {-10, -76},
            {-9, -78},
            {-8, -55},
            {-7, -111},
            {-6, -6},
            {-5, 23},
            {-4, 36},
            {-3, -12},
            {-2, -31},
            {-1, 89},
            {0, 123},
            {1, -110},
            {2, 2},
            {3, -89},
            {4, 0},
            {5, 52},
            {6, 71},
            {7, 8},
            {8, -36},
            {9, 50},
            {10, -74},
            {11, 12},
            {12, -15},
            {13, 119},
            {14, -51},
            {15, 105},
            {16, -27},
            {17, -49},
            {18, -17},
            {19, 74},
            {20, -70},
            {21, -112},
            {22, -50},
            {23, 85},
            {24, 106},
            {25, 32},
            {26, 93},
            {27, 25},
            {28, -98},
            {29, 120},
            {30, -108},
            {31, 28},
            {32, -20},
            {33, -127},
            {34, -53},
            {35, -29},
            {36, -105},
            {37, -72},
            {38, 3},
            {39, 122},
            {40, -116},
            {41, -101},
            {42, -125},
            {43, 62},
            {44, 24},
            {45, 86},
            {46, -119},
            {47, 121},
            {48, -14},
            {49, -80},
            {50, -63},
            {51, 26},
            {52, 118},
            {53, -9},
            {54, -88},
            {55, 75},
            {56, 112},
            {57, -103},
            {58, 15},
            {59, 92},
            {60, 102},
            {61, 29},
            {62, -124},
            {63, -87},
            {64, 30},
            {65, -65},
            {66, -79},
            {67, -106},
            {68, 80},
            {69, 104},
            {70, 95},
            {71, 117},
            {72, 98},
            {73, -128},
            {74, 37},
            {75, -104},
            {76, 5},
            {77, -3},
            {78, -85},
            {79, -61},
            {80, 49},
            {81, -96},
            {82, -92},
            {83, 124},
            {84, 84},
            {85, 110},
            {86, -24},
            {87, 60},
            {88, -102},
            {89, -67},
            {90, 90},
            {91, -41},
            {92, -25},
            {93, 34},
            {94, 82},
            {95, 17},
            {96, 115},
            {97, 96},
            {98, -121},
            {99, -43},
            {100, -7},
            {101, 88},
            {102, 77},
            {103, 116},
            {104, 51},
            {105, 61},
            {106, -81},
            {107, -126},
            {108, -84},
            {109, 70},
            {110, 6},
            {111, 47},
            {112, -68},
            {113, 21},
            {114, 48},
            {115, 81},
            {116, -64},
            {117, -91},
            {118, 19},
            {119, -22},
            {120, 66},
            {121, 27},
            {122, -35},
            {123, 40},
            {124, 41},
            {125, -10},
            {126, -97},
            {127, -62}
    };
}
