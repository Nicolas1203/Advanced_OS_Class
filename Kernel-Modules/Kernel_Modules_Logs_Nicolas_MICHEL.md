Results of codes seen in class 4
================================
Slide page 20
-------------

module code:

    #include <linux/module.h>
    #include <linux/kernel.h>
    #include <linux/init.h>
    #include <linux/gfp.h>

    #define PRINT_PREF "[LOWLEVEL]: "
    #define PAGES_ORDER_REQUESTED 3
    #define INTS_IN_PAGE (PAGE_SIZE/sizeof(int))

    unsigned long virt_addr;

    static int __init my_mod_init(void)
    {
        int *int_array;
        int i;

        printk(PRINT_PREF " Entering module.¥n");

            virt_addr = __get_free_pages(GFP_KERNEL, PAGES_ORDER_REQUESTED);
            if(!virt_addr) {
	            printk(PRINT_PREF " Error in allocation¥n ") ;
            return -1;
            }
        int_array = (int *)virt_addr;
        for(i=0; i<INTS_IN_PAGE; i++)
            int_array[i] = i;

	            for(i=0; i<INTS_IN_PAGE; i++)
		            printk(PRINT_PREF "array[%d] = %d¥n", i, int_array[i]);
        return 0;
    }

    static void __exit my_mod_exit(void)
    {
        free_pages(virt_addr, PAGES_ORDER_REQUESTED);
        printk(PRINT_PREF "Exiting module.¥n");
    }

    module_init(my_mod_init);
    module_exit(my_mod_exit);

output of printk()


    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325043] [LOWLEVEL]:  Entering module.¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325055] [LOWLEVEL]: array[0] = 0¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325057] [LOWLEVEL]: array[1] = 1¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325059] [LOWLEVEL]: array[2] = 2¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325061] [LOWLEVEL]: array[3] = 3¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325063] [LOWLEVEL]: array[4] = 4¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325065] [LOWLEVEL]: array[5] = 5¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325067] [LOWLEVEL]: array[6] = 6¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325068] [LOWLEVEL]: array[7] = 7¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325071] [LOWLEVEL]: array[8] = 8¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325072] [LOWLEVEL]: array[9] = 9¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325075] [LOWLEVEL]: array[10] = 10¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325077] [LOWLEVEL]: array[11] = 11¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325078] [LOWLEVEL]: array[12] = 12¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325080] [LOWLEVEL]: array[13] = 13¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325082] [LOWLEVEL]: array[14] = 14¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325084] [LOWLEVEL]: array[15] = 15¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325086] [LOWLEVEL]: array[16] = 16¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325088] [LOWLEVEL]: array[17] = 17¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325090] [LOWLEVEL]: array[18] = 18¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325092] [LOWLEVEL]: array[19] = 19¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325095] [LOWLEVEL]: array[20] = 20¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325097] [LOWLEVEL]: array[21] = 21¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325099] [LOWLEVEL]: array[22] = 22¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325101] [LOWLEVEL]: array[23] = 23¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325103] [LOWLEVEL]: array[24] = 24¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325105] [LOWLEVEL]: array[25] = 25¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325107] [LOWLEVEL]: array[26] = 26¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325109] [LOWLEVEL]: array[27] = 27¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325111] [LOWLEVEL]: array[28] = 28¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325113] [LOWLEVEL]: array[29] = 29¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325115] [LOWLEVEL]: array[30] = 30¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325117] [LOWLEVEL]: array[31] = 31¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325120] [LOWLEVEL]: array[32] = 32¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325121] [LOWLEVEL]: array[33] = 33¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325123] [LOWLEVEL]: array[34] = 34¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325125] [LOWLEVEL]: array[35] = 35¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325127] [LOWLEVEL]: array[36] = 36¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325130] [LOWLEVEL]: array[37] = 37¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325132] [LOWLEVEL]: array[38] = 38¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325134] [LOWLEVEL]: array[39] = 39¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325136] [LOWLEVEL]: array[40] = 40¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325138] [LOWLEVEL]: array[41] = 41¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325141] [LOWLEVEL]: array[42] = 42¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325143] [LOWLEVEL]: array[43] = 43¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325145] [LOWLEVEL]: array[44] = 44¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325147] [LOWLEVEL]: array[45] = 45¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325149] [LOWLEVEL]: array[46] = 46¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325151] [LOWLEVEL]: array[47] = 47¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325154] [LOWLEVEL]: array[48] = 48¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325156] [LOWLEVEL]: array[49] = 49¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325158] [LOWLEVEL]: array[50] = 50¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325160] [LOWLEVEL]: array[51] = 51¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325163] [LOWLEVEL]: array[52] = 52¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325165] [LOWLEVEL]: array[53] = 53¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325167] [LOWLEVEL]: array[54] = 54¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325169] [LOWLEVEL]: array[55] = 55¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325172] [LOWLEVEL]: array[56] = 56¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325174] [LOWLEVEL]: array[57] = 57¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325176] [LOWLEVEL]: array[58] = 58¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325178] [LOWLEVEL]: array[59] = 59¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325180] [LOWLEVEL]: array[60] = 60¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325182] [LOWLEVEL]: array[61] = 61¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325185] [LOWLEVEL]: array[62] = 62¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325187] [LOWLEVEL]: array[63] = 63¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325189] [LOWLEVEL]: array[64] = 64¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325192] [LOWLEVEL]: array[65] = 65¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325194] [LOWLEVEL]: array[66] = 66¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325196] [LOWLEVEL]: array[67] = 67¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325198] [LOWLEVEL]: array[68] = 68¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325200] [LOWLEVEL]: array[69] = 69¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325202] [LOWLEVEL]: array[70] = 70¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325204] [LOWLEVEL]: array[71] = 71¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325206] [LOWLEVEL]: array[72] = 72¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325208] [LOWLEVEL]: array[73] = 73¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325210] [LOWLEVEL]: array[74] = 74¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325212] [LOWLEVEL]: array[75] = 75¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325214] [LOWLEVEL]: array[76] = 76¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325216] [LOWLEVEL]: array[77] = 77¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325218] [LOWLEVEL]: array[78] = 78¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325220] [LOWLEVEL]: array[79] = 79¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325222] [LOWLEVEL]: array[80] = 80¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325224] [LOWLEVEL]: array[81] = 81¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325226] [LOWLEVEL]: array[82] = 82¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325227] [LOWLEVEL]: array[83] = 83¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325229] [LOWLEVEL]: array[84] = 84¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325231] [LOWLEVEL]: array[85] = 85¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325233] [LOWLEVEL]: array[86] = 86¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325235] [LOWLEVEL]: array[87] = 87¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325237] [LOWLEVEL]: array[88] = 88¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325239] [LOWLEVEL]: array[89] = 89¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325241] [LOWLEVEL]: array[90] = 90¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325243] [LOWLEVEL]: array[91] = 91¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325245] [LOWLEVEL]: array[92] = 92¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325247] [LOWLEVEL]: array[93] = 93¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325249] [LOWLEVEL]: array[94] = 94¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325251] [LOWLEVEL]: array[95] = 95¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325253] [LOWLEVEL]: array[96] = 96¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325255] [LOWLEVEL]: array[97] = 97¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325257] [LOWLEVEL]: array[98] = 98¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325259] [LOWLEVEL]: array[99] = 99¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325261] [LOWLEVEL]: array[100] = 100¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325263] [LOWLEVEL]: array[101] = 101¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325265] [LOWLEVEL]: array[102] = 102¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325268] [LOWLEVEL]: array[103] = 103¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325270] [LOWLEVEL]: array[104] = 104¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325272] [LOWLEVEL]: array[105] = 105¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325274] [LOWLEVEL]: array[106] = 106¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325277] [LOWLEVEL]: array[107] = 107¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325278] [LOWLEVEL]: array[108] = 108¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325280] [LOWLEVEL]: array[109] = 109¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325283] [LOWLEVEL]: array[110] = 110¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325285] [LOWLEVEL]: array[111] = 111¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325287] [LOWLEVEL]: array[112] = 112¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325289] [LOWLEVEL]: array[113] = 113¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325291] [LOWLEVEL]: array[114] = 114¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325294] [LOWLEVEL]: array[115] = 115¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325296] [LOWLEVEL]: array[116] = 116¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325298] [LOWLEVEL]: array[117] = 117¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325300] [LOWLEVEL]: array[118] = 118¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325302] [LOWLEVEL]: array[119] = 119¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325304] [LOWLEVEL]: array[120] = 120¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325306] [LOWLEVEL]: array[121] = 121¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325309] [LOWLEVEL]: array[122] = 122¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325310] [LOWLEVEL]: array[123] = 123¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325312] [LOWLEVEL]: array[124] = 124¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325314] [LOWLEVEL]: array[125] = 125¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325316] [LOWLEVEL]: array[126] = 126¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325319] [LOWLEVEL]: array[127] = 127¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325321] [LOWLEVEL]: array[128] = 128¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325323] [LOWLEVEL]: array[129] = 129¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325325] [LOWLEVEL]: array[130] = 130¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325327] [LOWLEVEL]: array[131] = 131¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325332] [LOWLEVEL]: array[132] = 132¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325334] [LOWLEVEL]: array[133] = 133¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325336] [LOWLEVEL]: array[134] = 134¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325339] [LOWLEVEL]: array[135] = 135¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325341] [LOWLEVEL]: array[136] = 136¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325343] [LOWLEVEL]: array[137] = 137¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325345] [LOWLEVEL]: array[138] = 138¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325348] [LOWLEVEL]: array[139] = 139¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325350] [LOWLEVEL]: array[140] = 140¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325352] [LOWLEVEL]: array[141] = 141¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325354] [LOWLEVEL]: array[142] = 142¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325356] [LOWLEVEL]: array[143] = 143¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325359] [LOWLEVEL]: array[144] = 144¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325361] [LOWLEVEL]: array[145] = 145¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325363] [LOWLEVEL]: array[146] = 146¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325365] [LOWLEVEL]: array[147] = 147¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325367] [LOWLEVEL]: array[148] = 148¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325369] [LOWLEVEL]: array[149] = 149¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325372] [LOWLEVEL]: array[150] = 150¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325374] [LOWLEVEL]: array[151] = 151¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325376] [LOWLEVEL]: array[152] = 152¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325378] [LOWLEVEL]: array[153] = 153¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325380] [LOWLEVEL]: array[154] = 154¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325382] [LOWLEVEL]: array[155] = 155¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325384] [LOWLEVEL]: array[156] = 156¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325386] [LOWLEVEL]: array[157] = 157¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325388] [LOWLEVEL]: array[158] = 158¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325390] [LOWLEVEL]: array[159] = 159¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325392] [LOWLEVEL]: array[160] = 160¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325393] [LOWLEVEL]: array[161] = 161¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325395] [LOWLEVEL]: array[162] = 162¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325397] [LOWLEVEL]: array[163] = 163¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325399] [LOWLEVEL]: array[164] = 164¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325401] [LOWLEVEL]: array[165] = 165¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325403] [LOWLEVEL]: array[166] = 166¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325405] [LOWLEVEL]: array[167] = 167¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325408] [LOWLEVEL]: array[168] = 168¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325410] [LOWLEVEL]: array[169] = 169¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325412] [LOWLEVEL]: array[170] = 170¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325414] [LOWLEVEL]: array[171] = 171¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325416] [LOWLEVEL]: array[172] = 172¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325418] [LOWLEVEL]: array[173] = 173¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325419] [LOWLEVEL]: array[174] = 174¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325421] [LOWLEVEL]: array[175] = 175¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325423] [LOWLEVEL]: array[176] = 176¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325425] [LOWLEVEL]: array[177] = 177¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325427] [LOWLEVEL]: array[178] = 178¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325429] [LOWLEVEL]: array[179] = 179¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325431] [LOWLEVEL]: array[180] = 180¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325433] [LOWLEVEL]: array[181] = 181¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325435] [LOWLEVEL]: array[182] = 182¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325437] [LOWLEVEL]: array[183] = 183¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325439] [LOWLEVEL]: array[184] = 184¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325441] [LOWLEVEL]: array[185] = 185¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325443] [LOWLEVEL]: array[186] = 186¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325445] [LOWLEVEL]: array[187] = 187¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325447] [LOWLEVEL]: array[188] = 188¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325449] [LOWLEVEL]: array[189] = 189¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325450] [LOWLEVEL]: array[190] = 190¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325452] [LOWLEVEL]: array[191] = 191¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325454] [LOWLEVEL]: array[192] = 192¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325456] [LOWLEVEL]: array[193] = 193¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325459] [LOWLEVEL]: array[194] = 194¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325461] [LOWLEVEL]: array[195] = 195¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325463] [LOWLEVEL]: array[196] = 196¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325465] [LOWLEVEL]: array[197] = 197¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325467] [LOWLEVEL]: array[198] = 198¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325469] [LOWLEVEL]: array[199] = 199¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325471] [LOWLEVEL]: array[200] = 200¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325473] [LOWLEVEL]: array[201] = 201¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325475] [LOWLEVEL]: array[202] = 202¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325477] [LOWLEVEL]: array[203] = 203¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325479] [LOWLEVEL]: array[204] = 204¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325481] [LOWLEVEL]: array[205] = 205¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325484] [LOWLEVEL]: array[206] = 206¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325486] [LOWLEVEL]: array[207] = 207¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325488] [LOWLEVEL]: array[208] = 208¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325490] [LOWLEVEL]: array[209] = 209¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325492] [LOWLEVEL]: array[210] = 210¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325494] [LOWLEVEL]: array[211] = 211¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325496] [LOWLEVEL]: array[212] = 212¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325498] [LOWLEVEL]: array[213] = 213¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325500] [LOWLEVEL]: array[214] = 214¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325502] [LOWLEVEL]: array[215] = 215¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325504] [LOWLEVEL]: array[216] = 216¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325506] [LOWLEVEL]: array[217] = 217¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325507] [LOWLEVEL]: array[218] = 218¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325509] [LOWLEVEL]: array[219] = 219¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325511] [LOWLEVEL]: array[220] = 220¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325513] [LOWLEVEL]: array[221] = 221¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325515] [LOWLEVEL]: array[222] = 222¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325517] [LOWLEVEL]: array[223] = 223¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325519] [LOWLEVEL]: array[224] = 224¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325521] [LOWLEVEL]: array[225] = 225¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325523] [LOWLEVEL]: array[226] = 226¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325525] [LOWLEVEL]: array[227] = 227¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325527] [LOWLEVEL]: array[228] = 228¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325529] [LOWLEVEL]: array[229] = 229¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325531] [LOWLEVEL]: array[230] = 230¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325533] [LOWLEVEL]: array[231] = 231¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325535] [LOWLEVEL]: array[232] = 232¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325536] [LOWLEVEL]: array[233] = 233¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325538] [LOWLEVEL]: array[234] = 234¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325540] [LOWLEVEL]: array[235] = 235¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325542] [LOWLEVEL]: array[236] = 236¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325544] [LOWLEVEL]: array[237] = 237¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325546] [LOWLEVEL]: array[238] = 238¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325548] [LOWLEVEL]: array[239] = 239¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325550] [LOWLEVEL]: array[240] = 240¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325552] [LOWLEVEL]: array[241] = 241¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325555] [LOWLEVEL]: array[242] = 242¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325557] [LOWLEVEL]: array[243] = 243¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325559] [LOWLEVEL]: array[244] = 244¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325561] [LOWLEVEL]: array[245] = 245¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325563] [LOWLEVEL]: array[246] = 246¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325565] [LOWLEVEL]: array[247] = 247¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325567] [LOWLEVEL]: array[248] = 248¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325569] [LOWLEVEL]: array[249] = 249¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325571] [LOWLEVEL]: array[250] = 250¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325573] [LOWLEVEL]: array[251] = 251¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325575] [LOWLEVEL]: array[252] = 252¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325577] [LOWLEVEL]: array[253] = 253¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325579] [LOWLEVEL]: array[254] = 254¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325581] [LOWLEVEL]: array[255] = 255¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325583] [LOWLEVEL]: array[256] = 256¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325586] [LOWLEVEL]: array[257] = 257¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325588] [LOWLEVEL]: array[258] = 258¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325590] [LOWLEVEL]: array[259] = 259¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325592] [LOWLEVEL]: array[260] = 260¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325594] [LOWLEVEL]: array[261] = 261¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325597] [LOWLEVEL]: array[262] = 262¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325598] [LOWLEVEL]: array[263] = 263¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325600] [LOWLEVEL]: array[264] = 264¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325603] [LOWLEVEL]: array[265] = 265¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325605] [LOWLEVEL]: array[266] = 266¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325607] [LOWLEVEL]: array[267] = 267¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325609] [LOWLEVEL]: array[268] = 268¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325611] [LOWLEVEL]: array[269] = 269¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325613] [LOWLEVEL]: array[270] = 270¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325616] [LOWLEVEL]: array[271] = 271¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325618] [LOWLEVEL]: array[272] = 272¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325620] [LOWLEVEL]: array[273] = 273¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325622] [LOWLEVEL]: array[274] = 274¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325624] [LOWLEVEL]: array[275] = 275¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325626] [LOWLEVEL]: array[276] = 276¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325628] [LOWLEVEL]: array[277] = 277¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325630] [LOWLEVEL]: array[278] = 278¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325632] [LOWLEVEL]: array[279] = 279¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325635] [LOWLEVEL]: array[280] = 280¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325637] [LOWLEVEL]: array[281] = 281¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325639] [LOWLEVEL]: array[282] = 282¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325641] [LOWLEVEL]: array[283] = 283¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325643] [LOWLEVEL]: array[284] = 284¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325645] [LOWLEVEL]: array[285] = 285¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325648] [LOWLEVEL]: array[286] = 286¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325650] [LOWLEVEL]: array[287] = 287¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325652] [LOWLEVEL]: array[288] = 288¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325655] [LOWLEVEL]: array[289] = 289¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325657] [LOWLEVEL]: array[290] = 290¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325659] [LOWLEVEL]: array[291] = 291¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325662] [LOWLEVEL]: array[292] = 292¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325664] [LOWLEVEL]: array[293] = 293¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325666] [LOWLEVEL]: array[294] = 294¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325668] [LOWLEVEL]: array[295] = 295¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325670] [LOWLEVEL]: array[296] = 296¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325672] [LOWLEVEL]: array[297] = 297¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325675] [LOWLEVEL]: array[298] = 298¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325677] [LOWLEVEL]: array[299] = 299¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325679] [LOWLEVEL]: array[300] = 300¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325681] [LOWLEVEL]: array[301] = 301¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325683] [LOWLEVEL]: array[302] = 302¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325685] [LOWLEVEL]: array[303] = 303¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325687] [LOWLEVEL]: array[304] = 304¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325690] [LOWLEVEL]: array[305] = 305¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325692] [LOWLEVEL]: array[306] = 306¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325694] [LOWLEVEL]: array[307] = 307¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325696] [LOWLEVEL]: array[308] = 308¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325698] [LOWLEVEL]: array[309] = 309¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325701] [LOWLEVEL]: array[310] = 310¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325703] [LOWLEVEL]: array[311] = 311¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325705] [LOWLEVEL]: array[312] = 312¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325707] [LOWLEVEL]: array[313] = 313¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325710] [LOWLEVEL]: array[314] = 314¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325712] [LOWLEVEL]: array[315] = 315¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325714] [LOWLEVEL]: array[316] = 316¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325716] [LOWLEVEL]: array[317] = 317¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325719] [LOWLEVEL]: array[318] = 318¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325721] [LOWLEVEL]: array[319] = 319¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325723] [LOWLEVEL]: array[320] = 320¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325725] [LOWLEVEL]: array[321] = 321¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325727] [LOWLEVEL]: array[322] = 322¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325729] [LOWLEVEL]: array[323] = 323¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325732] [LOWLEVEL]: array[324] = 324¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325734] [LOWLEVEL]: array[325] = 325¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325736] [LOWLEVEL]: array[326] = 326¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325738] [LOWLEVEL]: array[327] = 327¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325740] [LOWLEVEL]: array[328] = 328¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325742] [LOWLEVEL]: array[329] = 329¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325744] [LOWLEVEL]: array[330] = 330¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325747] [LOWLEVEL]: array[331] = 331¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325749] [LOWLEVEL]: array[332] = 332¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325751] [LOWLEVEL]: array[333] = 333¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325753] [LOWLEVEL]: array[334] = 334¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325755] [LOWLEVEL]: array[335] = 335¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325757] [LOWLEVEL]: array[336] = 336¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325759] [LOWLEVEL]: array[337] = 337¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325762] [LOWLEVEL]: array[338] = 338¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325764] [LOWLEVEL]: array[339] = 339¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325766] [LOWLEVEL]: array[340] = 340¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325768] [LOWLEVEL]: array[341] = 341¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325771] [LOWLEVEL]: array[342] = 342¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325773] [LOWLEVEL]: array[343] = 343¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325775] [LOWLEVEL]: array[344] = 344¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325777] [LOWLEVEL]: array[345] = 345¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325780] [LOWLEVEL]: array[346] = 346¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325782] [LOWLEVEL]: array[347] = 347¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325784] [LOWLEVEL]: array[348] = 348¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325786] [LOWLEVEL]: array[349] = 349¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325788] [LOWLEVEL]: array[350] = 350¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325790] [LOWLEVEL]: array[351] = 351¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325792] [LOWLEVEL]: array[352] = 352¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325794] [LOWLEVEL]: array[353] = 353¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325796] [LOWLEVEL]: array[354] = 354¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325798] [LOWLEVEL]: array[355] = 355¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325800] [LOWLEVEL]: array[356] = 356¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325802] [LOWLEVEL]: array[357] = 357¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325804] [LOWLEVEL]: array[358] = 358¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325806] [LOWLEVEL]: array[359] = 359¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325808] [LOWLEVEL]: array[360] = 360¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325810] [LOWLEVEL]: array[361] = 361¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325812] [LOWLEVEL]: array[362] = 362¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325814] [LOWLEVEL]: array[363] = 363¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325816] [LOWLEVEL]: array[364] = 364¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325818] [LOWLEVEL]: array[365] = 365¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325820] [LOWLEVEL]: array[366] = 366¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325822] [LOWLEVEL]: array[367] = 367¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325824] [LOWLEVEL]: array[368] = 368¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325826] [LOWLEVEL]: array[369] = 369¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325828] [LOWLEVEL]: array[370] = 370¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325830] [LOWLEVEL]: array[371] = 371¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325832] [LOWLEVEL]: array[372] = 372¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325834] [LOWLEVEL]: array[373] = 373¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325836] [LOWLEVEL]: array[374] = 374¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325838] [LOWLEVEL]: array[375] = 375¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325840] [LOWLEVEL]: array[376] = 376¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325843] [LOWLEVEL]: array[377] = 377¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325845] [LOWLEVEL]: array[378] = 378¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325847] [LOWLEVEL]: array[379] = 379¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325849] [LOWLEVEL]: array[380] = 380¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325851] [LOWLEVEL]: array[381] = 381¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325853] [LOWLEVEL]: array[382] = 382¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325855] [LOWLEVEL]: array[383] = 383¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325858] [LOWLEVEL]: array[384] = 384¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325860] [LOWLEVEL]: array[385] = 385¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325862] [LOWLEVEL]: array[386] = 386¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325864] [LOWLEVEL]: array[387] = 387¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325866] [LOWLEVEL]: array[388] = 388¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325868] [LOWLEVEL]: array[389] = 389¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325870] [LOWLEVEL]: array[390] = 390¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325872] [LOWLEVEL]: array[391] = 391¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325874] [LOWLEVEL]: array[392] = 392¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325877] [LOWLEVEL]: array[393] = 393¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325879] [LOWLEVEL]: array[394] = 394¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325881] [LOWLEVEL]: array[395] = 395¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325883] [LOWLEVEL]: array[396] = 396¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325885] [LOWLEVEL]: array[397] = 397¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325887] [LOWLEVEL]: array[398] = 398¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325889] [LOWLEVEL]: array[399] = 399¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325891] [LOWLEVEL]: array[400] = 400¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325893] [LOWLEVEL]: array[401] = 401¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325895] [LOWLEVEL]: array[402] = 402¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325897] [LOWLEVEL]: array[403] = 403¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325899] [LOWLEVEL]: array[404] = 404¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325902] [LOWLEVEL]: array[405] = 405¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325904] [LOWLEVEL]: array[406] = 406¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325906] [LOWLEVEL]: array[407] = 407¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325908] [LOWLEVEL]: array[408] = 408¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325910] [LOWLEVEL]: array[409] = 409¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325912] [LOWLEVEL]: array[410] = 410¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325914] [LOWLEVEL]: array[411] = 411¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325917] [LOWLEVEL]: array[412] = 412¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325918] [LOWLEVEL]: array[413] = 413¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325920] [LOWLEVEL]: array[414] = 414¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325923] [LOWLEVEL]: array[415] = 415¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325925] [LOWLEVEL]: array[416] = 416¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325926] [LOWLEVEL]: array[417] = 417¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325929] [LOWLEVEL]: array[418] = 418¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325931] [LOWLEVEL]: array[419] = 419¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325934] [LOWLEVEL]: array[420] = 420¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325936] [LOWLEVEL]: array[421] = 421¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325938] [LOWLEVEL]: array[422] = 422¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325940] [LOWLEVEL]: array[423] = 423¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325942] [LOWLEVEL]: array[424] = 424¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325944] [LOWLEVEL]: array[425] = 425¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325946] [LOWLEVEL]: array[426] = 426¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325948] [LOWLEVEL]: array[427] = 427¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325950] [LOWLEVEL]: array[428] = 428¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325952] [LOWLEVEL]: array[429] = 429¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325954] [LOWLEVEL]: array[430] = 430¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325956] [LOWLEVEL]: array[431] = 431¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325958] [LOWLEVEL]: array[432] = 432¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325960] [LOWLEVEL]: array[433] = 433¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325963] [LOWLEVEL]: array[434] = 434¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325965] [LOWLEVEL]: array[435] = 435¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325967] [LOWLEVEL]: array[436] = 436¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325969] [LOWLEVEL]: array[437] = 437¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325971] [LOWLEVEL]: array[438] = 438¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325973] [LOWLEVEL]: array[439] = 439¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325976] [LOWLEVEL]: array[440] = 440¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325978] [LOWLEVEL]: array[441] = 441¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325980] [LOWLEVEL]: array[442] = 442¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325981] [LOWLEVEL]: array[443] = 443¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325984] [LOWLEVEL]: array[444] = 444¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325985] [LOWLEVEL]: array[445] = 445¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325987] [LOWLEVEL]: array[446] = 446¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325989] [LOWLEVEL]: array[447] = 447¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325992] [LOWLEVEL]: array[448] = 448¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325993] [LOWLEVEL]: array[449] = 449¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325994] [LOWLEVEL]: array[450] = 450¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325996] [LOWLEVEL]: array[451] = 451¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325997] [LOWLEVEL]: array[452] = 452¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.325998] [LOWLEVEL]: array[453] = 453¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326000] [LOWLEVEL]: array[454] = 454¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326001] [LOWLEVEL]: array[455] = 455¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326002] [LOWLEVEL]: array[456] = 456¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326004] [LOWLEVEL]: array[457] = 457¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326005] [LOWLEVEL]: array[458] = 458¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326006] [LOWLEVEL]: array[459] = 459¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326008] [LOWLEVEL]: array[460] = 460¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326009] [LOWLEVEL]: array[461] = 461¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326011] [LOWLEVEL]: array[462] = 462¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326012] [LOWLEVEL]: array[463] = 463¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326013] [LOWLEVEL]: array[464] = 464¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326015] [LOWLEVEL]: array[465] = 465¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326016] [LOWLEVEL]: array[466] = 466¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326017] [LOWLEVEL]: array[467] = 467¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326019] [LOWLEVEL]: array[468] = 468¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326020] [LOWLEVEL]: array[469] = 469¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326021] [LOWLEVEL]: array[470] = 470¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326023] [LOWLEVEL]: array[471] = 471¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326024] [LOWLEVEL]: array[472] = 472¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326025] [LOWLEVEL]: array[473] = 473¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326027] [LOWLEVEL]: array[474] = 474¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326028] [LOWLEVEL]: array[475] = 475¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326029] [LOWLEVEL]: array[476] = 476¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326031] [LOWLEVEL]: array[477] = 477¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326032] [LOWLEVEL]: array[478] = 478¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326033] [LOWLEVEL]: array[479] = 479¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326035] [LOWLEVEL]: array[480] = 480¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326036] [LOWLEVEL]: array[481] = 481¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326037] [LOWLEVEL]: array[482] = 482¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326039] [LOWLEVEL]: array[483] = 483¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326040] [LOWLEVEL]: array[484] = 484¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326041] [LOWLEVEL]: array[485] = 485¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326043] [LOWLEVEL]: array[486] = 486¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326044] [LOWLEVEL]: array[487] = 487¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326045] [LOWLEVEL]: array[488] = 488¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326047] [LOWLEVEL]: array[489] = 489¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326048] [LOWLEVEL]: array[490] = 490¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326049] [LOWLEVEL]: array[491] = 491¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326051] [LOWLEVEL]: array[492] = 492¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326052] [LOWLEVEL]: array[493] = 493¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326053] [LOWLEVEL]: array[494] = 494¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326055] [LOWLEVEL]: array[495] = 495¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326056] [LOWLEVEL]: array[496] = 496¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326057] [LOWLEVEL]: array[497] = 497¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326059] [LOWLEVEL]: array[498] = 498¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326060] [LOWLEVEL]: array[499] = 499¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326061] [LOWLEVEL]: array[500] = 500¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326063] [LOWLEVEL]: array[501] = 501¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326064] [LOWLEVEL]: array[502] = 502¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326066] [LOWLEVEL]: array[503] = 503¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326067] [LOWLEVEL]: array[504] = 504¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326068] [LOWLEVEL]: array[505] = 505¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326070] [LOWLEVEL]: array[506] = 506¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326071] [LOWLEVEL]: array[507] = 507¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326072] [LOWLEVEL]: array[508] = 508¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326074] [LOWLEVEL]: array[509] = 509¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326075] [LOWLEVEL]: array[510] = 510¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326076] [LOWLEVEL]: array[511] = 511¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326078] [LOWLEVEL]: array[512] = 512¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326079] [LOWLEVEL]: array[513] = 513¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326080] [LOWLEVEL]: array[514] = 514¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326082] [LOWLEVEL]: array[515] = 515¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326083] [LOWLEVEL]: array[516] = 516¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326085] [LOWLEVEL]: array[517] = 517¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326086] [LOWLEVEL]: array[518] = 518¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326087] [LOWLEVEL]: array[519] = 519¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326089] [LOWLEVEL]: array[520] = 520¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326090] [LOWLEVEL]: array[521] = 521¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326091] [LOWLEVEL]: array[522] = 522¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326093] [LOWLEVEL]: array[523] = 523¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326094] [LOWLEVEL]: array[524] = 524¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326095] [LOWLEVEL]: array[525] = 525¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326097] [LOWLEVEL]: array[526] = 526¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326098] [LOWLEVEL]: array[527] = 527¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326099] [LOWLEVEL]: array[528] = 528¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326101] [LOWLEVEL]: array[529] = 529¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326102] [LOWLEVEL]: array[530] = 530¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326103] [LOWLEVEL]: array[531] = 531¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326105] [LOWLEVEL]: array[532] = 532¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326106] [LOWLEVEL]: array[533] = 533¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326107] [LOWLEVEL]: array[534] = 534¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326109] [LOWLEVEL]: array[535] = 535¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326110] [LOWLEVEL]: array[536] = 536¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326111] [LOWLEVEL]: array[537] = 537¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326113] [LOWLEVEL]: array[538] = 538¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326114] [LOWLEVEL]: array[539] = 539¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326115] [LOWLEVEL]: array[540] = 540¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326117] [LOWLEVEL]: array[541] = 541¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326118] [LOWLEVEL]: array[542] = 542¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326119] [LOWLEVEL]: array[543] = 543¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326121] [LOWLEVEL]: array[544] = 544¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326122] [LOWLEVEL]: array[545] = 545¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326123] [LOWLEVEL]: array[546] = 546¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326125] [LOWLEVEL]: array[547] = 547¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326126] [LOWLEVEL]: array[548] = 548¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326127] [LOWLEVEL]: array[549] = 549¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326129] [LOWLEVEL]: array[550] = 550¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326130] [LOWLEVEL]: array[551] = 551¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326131] [LOWLEVEL]: array[552] = 552¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326133] [LOWLEVEL]: array[553] = 553¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326134] [LOWLEVEL]: array[554] = 554¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326135] [LOWLEVEL]: array[555] = 555¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326137] [LOWLEVEL]: array[556] = 556¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326138] [LOWLEVEL]: array[557] = 557¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326140] [LOWLEVEL]: array[558] = 558¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326141] [LOWLEVEL]: array[559] = 559¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326143] [LOWLEVEL]: array[560] = 560¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326144] [LOWLEVEL]: array[561] = 561¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326145] [LOWLEVEL]: array[562] = 562¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326147] [LOWLEVEL]: array[563] = 563¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326148] [LOWLEVEL]: array[564] = 564¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326149] [LOWLEVEL]: array[565] = 565¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326150] [LOWLEVEL]: array[566] = 566¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326152] [LOWLEVEL]: array[567] = 567¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326153] [LOWLEVEL]: array[568] = 568¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326154] [LOWLEVEL]: array[569] = 569¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326156] [LOWLEVEL]: array[570] = 570¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326157] [LOWLEVEL]: array[571] = 571¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326158] [LOWLEVEL]: array[572] = 572¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326160] [LOWLEVEL]: array[573] = 573¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326161] [LOWLEVEL]: array[574] = 574¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326162] [LOWLEVEL]: array[575] = 575¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326164] [LOWLEVEL]: array[576] = 576¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326165] [LOWLEVEL]: array[577] = 577¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326166] [LOWLEVEL]: array[578] = 578¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326168] [LOWLEVEL]: array[579] = 579¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326169] [LOWLEVEL]: array[580] = 580¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326170] [LOWLEVEL]: array[581] = 581¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326172] [LOWLEVEL]: array[582] = 582¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326173] [LOWLEVEL]: array[583] = 583¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326174] [LOWLEVEL]: array[584] = 584¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326176] [LOWLEVEL]: array[585] = 585¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326177] [LOWLEVEL]: array[586] = 586¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326179] [LOWLEVEL]: array[587] = 587¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326180] [LOWLEVEL]: array[588] = 588¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326181] [LOWLEVEL]: array[589] = 589¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326183] [LOWLEVEL]: array[590] = 590¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326184] [LOWLEVEL]: array[591] = 591¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326185] [LOWLEVEL]: array[592] = 592¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326187] [LOWLEVEL]: array[593] = 593¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326188] [LOWLEVEL]: array[594] = 594¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326189] [LOWLEVEL]: array[595] = 595¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326191] [LOWLEVEL]: array[596] = 596¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326192] [LOWLEVEL]: array[597] = 597¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326193] [LOWLEVEL]: array[598] = 598¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326195] [LOWLEVEL]: array[599] = 599¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326196] [LOWLEVEL]: array[600] = 600¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326197] [LOWLEVEL]: array[601] = 601¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326199] [LOWLEVEL]: array[602] = 602¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326200] [LOWLEVEL]: array[603] = 603¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326201] [LOWLEVEL]: array[604] = 604¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326203] [LOWLEVEL]: array[605] = 605¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326204] [LOWLEVEL]: array[606] = 606¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326205] [LOWLEVEL]: array[607] = 607¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326207] [LOWLEVEL]: array[608] = 608¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326208] [LOWLEVEL]: array[609] = 609¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326209] [LOWLEVEL]: array[610] = 610¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326211] [LOWLEVEL]: array[611] = 611¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326212] [LOWLEVEL]: array[612] = 612¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326214] [LOWLEVEL]: array[613] = 613¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326215] [LOWLEVEL]: array[614] = 614¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326216] [LOWLEVEL]: array[615] = 615¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326218] [LOWLEVEL]: array[616] = 616¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326219] [LOWLEVEL]: array[617] = 617¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326220] [LOWLEVEL]: array[618] = 618¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326222] [LOWLEVEL]: array[619] = 619¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326223] [LOWLEVEL]: array[620] = 620¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326224] [LOWLEVEL]: array[621] = 621¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326226] [LOWLEVEL]: array[622] = 622¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326227] [LOWLEVEL]: array[623] = 623¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326228] [LOWLEVEL]: array[624] = 624¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326230] [LOWLEVEL]: array[625] = 625¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326231] [LOWLEVEL]: array[626] = 626¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326232] [LOWLEVEL]: array[627] = 627¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326234] [LOWLEVEL]: array[628] = 628¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326235] [LOWLEVEL]: array[629] = 629¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326236] [LOWLEVEL]: array[630] = 630¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326238] [LOWLEVEL]: array[631] = 631¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326239] [LOWLEVEL]: array[632] = 632¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326240] [LOWLEVEL]: array[633] = 633¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326242] [LOWLEVEL]: array[634] = 634¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326243] [LOWLEVEL]: array[635] = 635¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326244] [LOWLEVEL]: array[636] = 636¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326246] [LOWLEVEL]: array[637] = 637¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326247] [LOWLEVEL]: array[638] = 638¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326249] [LOWLEVEL]: array[639] = 639¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326250] [LOWLEVEL]: array[640] = 640¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326251] [LOWLEVEL]: array[641] = 641¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326253] [LOWLEVEL]: array[642] = 642¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326254] [LOWLEVEL]: array[643] = 643¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326255] [LOWLEVEL]: array[644] = 644¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326257] [LOWLEVEL]: array[645] = 645¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326258] [LOWLEVEL]: array[646] = 646¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326259] [LOWLEVEL]: array[647] = 647¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326261] [LOWLEVEL]: array[648] = 648¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326262] [LOWLEVEL]: array[649] = 649¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326263] [LOWLEVEL]: array[650] = 650¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326265] [LOWLEVEL]: array[651] = 651¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326266] [LOWLEVEL]: array[652] = 652¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326267] [LOWLEVEL]: array[653] = 653¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326269] [LOWLEVEL]: array[654] = 654¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326270] [LOWLEVEL]: array[655] = 655¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326271] [LOWLEVEL]: array[656] = 656¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326273] [LOWLEVEL]: array[657] = 657¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326274] [LOWLEVEL]: array[658] = 658¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326275] [LOWLEVEL]: array[659] = 659¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326277] [LOWLEVEL]: array[660] = 660¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326278] [LOWLEVEL]: array[661] = 661¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326280] [LOWLEVEL]: array[662] = 662¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326281] [LOWLEVEL]: array[663] = 663¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326282] [LOWLEVEL]: array[664] = 664¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326284] [LOWLEVEL]: array[665] = 665¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326285] [LOWLEVEL]: array[666] = 666¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326286] [LOWLEVEL]: array[667] = 667¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326288] [LOWLEVEL]: array[668] = 668¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326289] [LOWLEVEL]: array[669] = 669¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326290] [LOWLEVEL]: array[670] = 670¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326292] [LOWLEVEL]: array[671] = 671¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326293] [LOWLEVEL]: array[672] = 672¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326294] [LOWLEVEL]: array[673] = 673¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326296] [LOWLEVEL]: array[674] = 674¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326297] [LOWLEVEL]: array[675] = 675¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326298] [LOWLEVEL]: array[676] = 676¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326300] [LOWLEVEL]: array[677] = 677¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326301] [LOWLEVEL]: array[678] = 678¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326302] [LOWLEVEL]: array[679] = 679¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326304] [LOWLEVEL]: array[680] = 680¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326305] [LOWLEVEL]: array[681] = 681¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326307] [LOWLEVEL]: array[682] = 682¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326308] [LOWLEVEL]: array[683] = 683¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326309] [LOWLEVEL]: array[684] = 684¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326311] [LOWLEVEL]: array[685] = 685¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326312] [LOWLEVEL]: array[686] = 686¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326313] [LOWLEVEL]: array[687] = 687¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326315] [LOWLEVEL]: array[688] = 688¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326316] [LOWLEVEL]: array[689] = 689¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326317] [LOWLEVEL]: array[690] = 690¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326319] [LOWLEVEL]: array[691] = 691¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326320] [LOWLEVEL]: array[692] = 692¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326321] [LOWLEVEL]: array[693] = 693¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326323] [LOWLEVEL]: array[694] = 694¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326324] [LOWLEVEL]: array[695] = 695¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326325] [LOWLEVEL]: array[696] = 696¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326327] [LOWLEVEL]: array[697] = 697¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326328] [LOWLEVEL]: array[698] = 698¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326329] [LOWLEVEL]: array[699] = 699¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326331] [LOWLEVEL]: array[700] = 700¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326332] [LOWLEVEL]: array[701] = 701¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326333] [LOWLEVEL]: array[702] = 702¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326335] [LOWLEVEL]: array[703] = 703¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326336] [LOWLEVEL]: array[704] = 704¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326337] [LOWLEVEL]: array[705] = 705¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326339] [LOWLEVEL]: array[706] = 706¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326340] [LOWLEVEL]: array[707] = 707¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326342] [LOWLEVEL]: array[708] = 708¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326343] [LOWLEVEL]: array[709] = 709¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326344] [LOWLEVEL]: array[710] = 710¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326346] [LOWLEVEL]: array[711] = 711¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326347] [LOWLEVEL]: array[712] = 712¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326349] [LOWLEVEL]: array[713] = 713¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326350] [LOWLEVEL]: array[714] = 714¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326351] [LOWLEVEL]: array[715] = 715¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326353] [LOWLEVEL]: array[716] = 716¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326354] [LOWLEVEL]: array[717] = 717¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326355] [LOWLEVEL]: array[718] = 718¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326357] [LOWLEVEL]: array[719] = 719¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326358] [LOWLEVEL]: array[720] = 720¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326359] [LOWLEVEL]: array[721] = 721¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326361] [LOWLEVEL]: array[722] = 722¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326362] [LOWLEVEL]: array[723] = 723¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326363] [LOWLEVEL]: array[724] = 724¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326365] [LOWLEVEL]: array[725] = 725¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326366] [LOWLEVEL]: array[726] = 726¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326367] [LOWLEVEL]: array[727] = 727¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326369] [LOWLEVEL]: array[728] = 728¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326370] [LOWLEVEL]: array[729] = 729¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326371] [LOWLEVEL]: array[730] = 730¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326373] [LOWLEVEL]: array[731] = 731¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326374] [LOWLEVEL]: array[732] = 732¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326375] [LOWLEVEL]: array[733] = 733¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326377] [LOWLEVEL]: array[734] = 734¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326378] [LOWLEVEL]: array[735] = 735¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326379] [LOWLEVEL]: array[736] = 736¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326381] [LOWLEVEL]: array[737] = 737¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326382] [LOWLEVEL]: array[738] = 738¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326383] [LOWLEVEL]: array[739] = 739¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326385] [LOWLEVEL]: array[740] = 740¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326386] [LOWLEVEL]: array[741] = 741¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326387] [LOWLEVEL]: array[742] = 742¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326389] [LOWLEVEL]: array[743] = 743¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326390] [LOWLEVEL]: array[744] = 744¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326391] [LOWLEVEL]: array[745] = 745¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326393] [LOWLEVEL]: array[746] = 746¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326394] [LOWLEVEL]: array[747] = 747¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326395] [LOWLEVEL]: array[748] = 748¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326397] [LOWLEVEL]: array[749] = 749¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326398] [LOWLEVEL]: array[750] = 750¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326399] [LOWLEVEL]: array[751] = 751¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326401] [LOWLEVEL]: array[752] = 752¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326402] [LOWLEVEL]: array[753] = 753¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326403] [LOWLEVEL]: array[754] = 754¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326405] [LOWLEVEL]: array[755] = 755¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326406] [LOWLEVEL]: array[756] = 756¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326407] [LOWLEVEL]: array[757] = 757¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326409] [LOWLEVEL]: array[758] = 758¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326410] [LOWLEVEL]: array[759] = 759¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326411] [LOWLEVEL]: array[760] = 760¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326413] [LOWLEVEL]: array[761] = 761¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326414] [LOWLEVEL]: array[762] = 762¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326416] [LOWLEVEL]: array[763] = 763¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326417] [LOWLEVEL]: array[764] = 764¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326418] [LOWLEVEL]: array[765] = 765¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326420] [LOWLEVEL]: array[766] = 766¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326421] [LOWLEVEL]: array[767] = 767¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326422] [LOWLEVEL]: array[768] = 768¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326424] [LOWLEVEL]: array[769] = 769¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326425] [LOWLEVEL]: array[770] = 770¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326426] [LOWLEVEL]: array[771] = 771¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326428] [LOWLEVEL]: array[772] = 772¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326429] [LOWLEVEL]: array[773] = 773¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326430] [LOWLEVEL]: array[774] = 774¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326432] [LOWLEVEL]: array[775] = 775¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326433] [LOWLEVEL]: array[776] = 776¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326434] [LOWLEVEL]: array[777] = 777¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326436] [LOWLEVEL]: array[778] = 778¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326437] [LOWLEVEL]: array[779] = 779¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326438] [LOWLEVEL]: array[780] = 780¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326440] [LOWLEVEL]: array[781] = 781¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326441] [LOWLEVEL]: array[782] = 782¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326442] [LOWLEVEL]: array[783] = 783¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326444] [LOWLEVEL]: array[784] = 784¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326445] [LOWLEVEL]: array[785] = 785¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326447] [LOWLEVEL]: array[786] = 786¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326448] [LOWLEVEL]: array[787] = 787¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326449] [LOWLEVEL]: array[788] = 788¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326451] [LOWLEVEL]: array[789] = 789¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326452] [LOWLEVEL]: array[790] = 790¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326453] [LOWLEVEL]: array[791] = 791¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326455] [LOWLEVEL]: array[792] = 792¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326456] [LOWLEVEL]: array[793] = 793¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326457] [LOWLEVEL]: array[794] = 794¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326459] [LOWLEVEL]: array[795] = 795¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326460] [LOWLEVEL]: array[796] = 796¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326461] [LOWLEVEL]: array[797] = 797¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326463] [LOWLEVEL]: array[798] = 798¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326464] [LOWLEVEL]: array[799] = 799¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326465] [LOWLEVEL]: array[800] = 800¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326467] [LOWLEVEL]: array[801] = 801¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326468] [LOWLEVEL]: array[802] = 802¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326469] [LOWLEVEL]: array[803] = 803¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326471] [LOWLEVEL]: array[804] = 804¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326472] [LOWLEVEL]: array[805] = 805¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326474] [LOWLEVEL]: array[806] = 806¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326475] [LOWLEVEL]: array[807] = 807¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326476] [LOWLEVEL]: array[808] = 808¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326478] [LOWLEVEL]: array[809] = 809¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326479] [LOWLEVEL]: array[810] = 810¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326480] [LOWLEVEL]: array[811] = 811¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326482] [LOWLEVEL]: array[812] = 812¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326483] [LOWLEVEL]: array[813] = 813¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326484] [LOWLEVEL]: array[814] = 814¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326486] [LOWLEVEL]: array[815] = 815¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326487] [LOWLEVEL]: array[816] = 816¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326488] [LOWLEVEL]: array[817] = 817¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326490] [LOWLEVEL]: array[818] = 818¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326491] [LOWLEVEL]: array[819] = 819¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326492] [LOWLEVEL]: array[820] = 820¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326494] [LOWLEVEL]: array[821] = 821¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326495] [LOWLEVEL]: array[822] = 822¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326496] [LOWLEVEL]: array[823] = 823¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326498] [LOWLEVEL]: array[824] = 824¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326499] [LOWLEVEL]: array[825] = 825¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326500] [LOWLEVEL]: array[826] = 826¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326502] [LOWLEVEL]: array[827] = 827¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326503] [LOWLEVEL]: array[828] = 828¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326505] [LOWLEVEL]: array[829] = 829¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326506] [LOWLEVEL]: array[830] = 830¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326507] [LOWLEVEL]: array[831] = 831¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326509] [LOWLEVEL]: array[832] = 832¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326510] [LOWLEVEL]: array[833] = 833¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326511] [LOWLEVEL]: array[834] = 834¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326513] [LOWLEVEL]: array[835] = 835¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326514] [LOWLEVEL]: array[836] = 836¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326515] [LOWLEVEL]: array[837] = 837¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326517] [LOWLEVEL]: array[838] = 838¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326518] [LOWLEVEL]: array[839] = 839¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326519] [LOWLEVEL]: array[840] = 840¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326521] [LOWLEVEL]: array[841] = 841¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326522] [LOWLEVEL]: array[842] = 842¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326523] [LOWLEVEL]: array[843] = 843¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326525] [LOWLEVEL]: array[844] = 844¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326526] [LOWLEVEL]: array[845] = 845¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326528] [LOWLEVEL]: array[846] = 846¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326529] [LOWLEVEL]: array[847] = 847¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326530] [LOWLEVEL]: array[848] = 848¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326532] [LOWLEVEL]: array[849] = 849¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326533] [LOWLEVEL]: array[850] = 850¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326534] [LOWLEVEL]: array[851] = 851¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326536] [LOWLEVEL]: array[852] = 852¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326537] [LOWLEVEL]: array[853] = 853¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326538] [LOWLEVEL]: array[854] = 854¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326540] [LOWLEVEL]: array[855] = 855¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326541] [LOWLEVEL]: array[856] = 856¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326542] [LOWLEVEL]: array[857] = 857¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326544] [LOWLEVEL]: array[858] = 858¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326545] [LOWLEVEL]: array[859] = 859¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326546] [LOWLEVEL]: array[860] = 860¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326548] [LOWLEVEL]: array[861] = 861¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326549] [LOWLEVEL]: array[862] = 862¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326550] [LOWLEVEL]: array[863] = 863¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326552] [LOWLEVEL]: array[864] = 864¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326553] [LOWLEVEL]: array[865] = 865¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326554] [LOWLEVEL]: array[866] = 866¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326556] [LOWLEVEL]: array[867] = 867¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326557] [LOWLEVEL]: array[868] = 868¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326558] [LOWLEVEL]: array[869] = 869¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326560] [LOWLEVEL]: array[870] = 870¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326561] [LOWLEVEL]: array[871] = 871¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326562] [LOWLEVEL]: array[872] = 872¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326564] [LOWLEVEL]: array[873] = 873¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326565] [LOWLEVEL]: array[874] = 874¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326566] [LOWLEVEL]: array[875] = 875¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326568] [LOWLEVEL]: array[876] = 876¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326569] [LOWLEVEL]: array[877] = 877¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326571] [LOWLEVEL]: array[878] = 878¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326572] [LOWLEVEL]: array[879] = 879¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326573] [LOWLEVEL]: array[880] = 880¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326575] [LOWLEVEL]: array[881] = 881¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326576] [LOWLEVEL]: array[882] = 882¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326577] [LOWLEVEL]: array[883] = 883¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326579] [LOWLEVEL]: array[884] = 884¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326580] [LOWLEVEL]: array[885] = 885¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326581] [LOWLEVEL]: array[886] = 886¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326583] [LOWLEVEL]: array[887] = 887¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326584] [LOWLEVEL]: array[888] = 888¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326585] [LOWLEVEL]: array[889] = 889¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326587] [LOWLEVEL]: array[890] = 890¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326588] [LOWLEVEL]: array[891] = 891¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326589] [LOWLEVEL]: array[892] = 892¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326591] [LOWLEVEL]: array[893] = 893¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326592] [LOWLEVEL]: array[894] = 894¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326593] [LOWLEVEL]: array[895] = 895¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326595] [LOWLEVEL]: array[896] = 896¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326596] [LOWLEVEL]: array[897] = 897¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326598] [LOWLEVEL]: array[898] = 898¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326599] [LOWLEVEL]: array[899] = 899¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326600] [LOWLEVEL]: array[900] = 900¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326602] [LOWLEVEL]: array[901] = 901¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326603] [LOWLEVEL]: array[902] = 902¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326604] [LOWLEVEL]: array[903] = 903¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326606] [LOWLEVEL]: array[904] = 904¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326607] [LOWLEVEL]: array[905] = 905¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326608] [LOWLEVEL]: array[906] = 906¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326610] [LOWLEVEL]: array[907] = 907¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326611] [LOWLEVEL]: array[908] = 908¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326612] [LOWLEVEL]: array[909] = 909¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326614] [LOWLEVEL]: array[910] = 910¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326615] [LOWLEVEL]: array[911] = 911¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326616] [LOWLEVEL]: array[912] = 912¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326618] [LOWLEVEL]: array[913] = 913¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326619] [LOWLEVEL]: array[914] = 914¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326620] [LOWLEVEL]: array[915] = 915¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326622] [LOWLEVEL]: array[916] = 916¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326623] [LOWLEVEL]: array[917] = 917¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326625] [LOWLEVEL]: array[918] = 918¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326626] [LOWLEVEL]: array[919] = 919¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326627] [LOWLEVEL]: array[920] = 920¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326629] [LOWLEVEL]: array[921] = 921¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326630] [LOWLEVEL]: array[922] = 922¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326631] [LOWLEVEL]: array[923] = 923¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326633] [LOWLEVEL]: array[924] = 924¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326634] [LOWLEVEL]: array[925] = 925¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326635] [LOWLEVEL]: array[926] = 926¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326637] [LOWLEVEL]: array[927] = 927¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326638] [LOWLEVEL]: array[928] = 928¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326639] [LOWLEVEL]: array[929] = 929¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326641] [LOWLEVEL]: array[930] = 930¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326642] [LOWLEVEL]: array[931] = 931¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326643] [LOWLEVEL]: array[932] = 932¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326645] [LOWLEVEL]: array[933] = 933¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326646] [LOWLEVEL]: array[934] = 934¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326647] [LOWLEVEL]: array[935] = 935¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326649] [LOWLEVEL]: array[936] = 936¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326650] [LOWLEVEL]: array[937] = 937¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326651] [LOWLEVEL]: array[938] = 938¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326653] [LOWLEVEL]: array[939] = 939¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326654] [LOWLEVEL]: array[940] = 940¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326655] [LOWLEVEL]: array[941] = 941¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326657] [LOWLEVEL]: array[942] = 942¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326658] [LOWLEVEL]: array[943] = 943¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326659] [LOWLEVEL]: array[944] = 944¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326661] [LOWLEVEL]: array[945] = 945¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326662] [LOWLEVEL]: array[946] = 946¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326663] [LOWLEVEL]: array[947] = 947¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326665] [LOWLEVEL]: array[948] = 948¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326666] [LOWLEVEL]: array[949] = 949¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326668] [LOWLEVEL]: array[950] = 950¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326669] [LOWLEVEL]: array[951] = 951¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326670] [LOWLEVEL]: array[952] = 952¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326672] [LOWLEVEL]: array[953] = 953¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326673] [LOWLEVEL]: array[954] = 954¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326674] [LOWLEVEL]: array[955] = 955¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326676] [LOWLEVEL]: array[956] = 956¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326677] [LOWLEVEL]: array[957] = 957¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326678] [LOWLEVEL]: array[958] = 958¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326680] [LOWLEVEL]: array[959] = 959¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326681] [LOWLEVEL]: array[960] = 960¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326682] [LOWLEVEL]: array[961] = 961¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326684] [LOWLEVEL]: array[962] = 962¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326685] [LOWLEVEL]: array[963] = 963¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326686] [LOWLEVEL]: array[964] = 964¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326688] [LOWLEVEL]: array[965] = 965¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326689] [LOWLEVEL]: array[966] = 966¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326690] [LOWLEVEL]: array[967] = 967¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326692] [LOWLEVEL]: array[968] = 968¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326693] [LOWLEVEL]: array[969] = 969¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326694] [LOWLEVEL]: array[970] = 970¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326696] [LOWLEVEL]: array[971] = 971¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326697] [LOWLEVEL]: array[972] = 972¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326698] [LOWLEVEL]: array[973] = 973¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326700] [LOWLEVEL]: array[974] = 974¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326701] [LOWLEVEL]: array[975] = 975¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326702] [LOWLEVEL]: array[976] = 976¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326704] [LOWLEVEL]: array[977] = 977¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326705] [LOWLEVEL]: array[978] = 978¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326706] [LOWLEVEL]: array[979] = 979¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326708] [LOWLEVEL]: array[980] = 980¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326709] [LOWLEVEL]: array[981] = 981¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326710] [LOWLEVEL]: array[982] = 982¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326712] [LOWLEVEL]: array[983] = 983¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326713] [LOWLEVEL]: array[984] = 984¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326714] [LOWLEVEL]: array[985] = 985¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326716] [LOWLEVEL]: array[986] = 986¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326717] [LOWLEVEL]: array[987] = 987¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326719] [LOWLEVEL]: array[988] = 988¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326720] [LOWLEVEL]: array[989] = 989¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326721] [LOWLEVEL]: array[990] = 990¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326723] [LOWLEVEL]: array[991] = 991¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326724] [LOWLEVEL]: array[992] = 992¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326725] [LOWLEVEL]: array[993] = 993¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326727] [LOWLEVEL]: array[994] = 994¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326728] [LOWLEVEL]: array[995] = 995¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326729] [LOWLEVEL]: array[996] = 996¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326731] [LOWLEVEL]: array[997] = 997¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326732] [LOWLEVEL]: array[998] = 998¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326733] [LOWLEVEL]: array[999] = 999¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326735] [LOWLEVEL]: array[1000] = 1000¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326736] [LOWLEVEL]: array[1001] = 1001¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326738] [LOWLEVEL]: array[1002] = 1002¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326739] [LOWLEVEL]: array[1003] = 1003¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326740] [LOWLEVEL]: array[1004] = 1004¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326742] [LOWLEVEL]: array[1005] = 1005¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326743] [LOWLEVEL]: array[1006] = 1006¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326744] [LOWLEVEL]: array[1007] = 1007¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326746] [LOWLEVEL]: array[1008] = 1008¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326747] [LOWLEVEL]: array[1009] = 1009¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326748] [LOWLEVEL]: array[1010] = 1010¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326750] [LOWLEVEL]: array[1011] = 1011¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326751] [LOWLEVEL]: array[1012] = 1012¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326752] [LOWLEVEL]: array[1013] = 1013¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326754] [LOWLEVEL]: array[1014] = 1014¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326755] [LOWLEVEL]: array[1015] = 1015¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326756] [LOWLEVEL]: array[1016] = 1016¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326758] [LOWLEVEL]: array[1017] = 1017¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326759] [LOWLEVEL]: array[1018] = 1018¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326761] [LOWLEVEL]: array[1019] = 1019¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326762] [LOWLEVEL]: array[1020] = 1020¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326763] [LOWLEVEL]: array[1021] = 1021¥n
    Nov 20 19:06:03 nicolas-Lemur kernel: [ 7865.326765] [LOWLEVEL]: array[1022] = 1022¥n



Slide page 33
------------


module code


    #include <linux/module.h>
    #include <linux/kernel.h>
    #include <linux/init.h>
    #include <linux/gfp.h>
    #include <linux/slab.h>

    #define PRINT_PREF "[KMALLOC_TEST]: "

    static int __init my_mod_init(void)
    {
        unsigned long i;
        void *ptr;

        printk(PRINT_PREF " Entering module.¥n");

        for (i=1;;i*=2) {
            ptr = kmalloc(i, GFP_KERNEL);
            if(!ptr) {
                printk(PRINT_PREF "could not allocate %lu bytes¥n", i) ;
                break;
            }
            kfree(ptr);
        }

        return 0;
    }

    static void __exit my_mod_exit(void)
    {
        printk(PRINT_PREF "Exiting module.¥n");
    }

    module_init(my_mod_init);
    module_exit(my_mod_exit);

    MODULE_LICENSE("GPL");




out of printk()


            Nov 20 19:28:57 nicolas-Lemur kernel: [ 9239.931712] [KMALLOC_TEST]:  Entering module.¥n
            Nov 20 19:28:57 nicolas-Lemur kernel: [ 9239.931792] ------------[ cut here ]------------
            Nov 20 19:28:57 nicolas-Lemur kernel: [ 9239.931800] WARNING: CPU: 3 PID: 17749 at /build/linux-zYxhRZ/linux-4.10.0/mm/page_alloc.c:3542 __alloc_pages_slowpath+0x9fe/0xba0
            Nov 20 19:28:57 nicolas-Lemur kernel: [ 9239.931801] Modules linked in: kmallocANDvmalloc(OE+) hid_generic hidp ccm rfcomm ec_sys cmac bnep snd_hda_codec_hdmi snd_hda_codec_realtek snd_hda_codec_generic binfmt_misc nls_iso8859_1 snd_soc_skl snd_soc_skl_ipc snd_soc_sst_ipc snd_soc_sst_dsp snd_hda_ext_core snd_soc_sst_match snd_soc_core snd_compress ac97_bus snd_pcm_dmaengine arc4 snd_hda_intel snd_hda_codec snd_hda_core snd_hwdep intel_rapl x86_pkg_temp_thermal intel_powerclamp coretemp snd_pcm kvm_intel kvm irqbypass snd_seq_midi snd_seq_midi_event crct10dif_pclmul snd_rawmidi crc32_pclmul ghash_clmulni_intel pcbc aesni_intel uvcvideo aes_x86_64 snd_seq iwlmvm crypto_simd glue_helper cryptd mac80211 videobuf2_vmalloc snd_seq_device videobuf2_memops snd_timer input_leds videobuf2_v4l2 joydev videobuf2_core videodev iwlwifi serio_raw media
            Nov 20 19:28:57 nicolas-Lemur kernel: [ 9239.931842]  snd rtsx_pci_ms cfg80211 memstick soundcore btusb mei_me shpchp btrtl mei intel_pch_thermal hci_uart btbcm btqca btintel bluetooth intel_lpss_acpi intel_lpss mac_hid tpm_crb acpi_pad parport_pc ppdev lp parport ip_tables x_tables autofs4 btrfs xor raid6_pq dm_mirror dm_region_hash dm_log rtsx_pci_sdmmc i915 i2c_algo_bit drm_kms_helper syscopyarea sysfillrect psmouse sysimgblt r8169 fb_sys_fops mii drm ahci rtsx_pci libahci wmi i2c_hid video hid pinctrl_sunrisepoint pinctrl_intel fjes [last unloaded: llma]
            Nov 20 19:28:57 nicolas-Lemur kernel: [ 9239.931881] CPU: 3 PID: 17749 Comm: insmod Tainted: P           OE   4.10.0-38-generic #42-Ubuntu
            Nov 20 19:28:57 nicolas-Lemur kernel: [ 9239.931882] Hardware name: System76                        Lemur/Lemur, BIOS 5.12 02/17/2017
            Nov 20 19:28:57 nicolas-Lemur kernel: [ 9239.931883] Call Trace:
            Nov 20 19:28:57 nicolas-Lemur kernel: [ 9239.931890]  dump_stack+0x63/0x81
            Nov 20 19:28:57 nicolas-Lemur kernel: [ 9239.931893]  __warn+0xcb/0xf0
            Nov 20 19:28:57 nicolas-Lemur kernel: [ 9239.931895]  warn_slowpath_null+0x1d/0x20
            Nov 20 19:28:57 nicolas-Lemur kernel: [ 9239.931897]  __alloc_pages_slowpath+0x9fe/0xba0
            Nov 20 19:28:57 nicolas-Lemur kernel: [ 9239.931900]  ? get_page_from_freelist+0x46a/0xb20
            Nov 20 19:28:57 nicolas-Lemur kernel: [ 9239.931903]  __alloc_pages_nodemask+0x209/0x260
            Nov 20 19:28:57 nicolas-Lemur kernel: [ 9239.931907]  alloc_pages_current+0x95/0x140
            Nov 20 19:28:57 nicolas-Lemur kernel: [ 9239.931910]  kmalloc_order+0x18/0x40
            Nov 20 19:28:57 nicolas-Lemur kernel: [ 9239.931912]  kmalloc_order_trace+0x24/0xa0
            Nov 20 19:28:57 nicolas-Lemur kernel: [ 9239.931915]  ? __kmalloc+0x1c7/0x1e0
            Nov 20 19:28:57 nicolas-Lemur kernel: [ 9239.931917]  __kmalloc+0x1c7/0x1e0
            Nov 20 19:28:57 nicolas-Lemur kernel: [ 9239.931919]  ? __free_pages+0x18/0x30
            Nov 20 19:28:57 nicolas-Lemur kernel: [ 9239.931924]  my_mod_init+0x23/0x1000 [kmallocANDvmalloc]
            Nov 20 19:28:57 nicolas-Lemur kernel: [ 9239.931925]  ? 0xffffffffc0322000
            Nov 20 19:28:57 nicolas-Lemur kernel: [ 9239.931928]  do_one_initcall+0x52/0x1b0
            Nov 20 19:28:57 nicolas-Lemur kernel: [ 9239.931931]  ? kmem_cache_alloc_trace+0xd7/0x190
            Nov 20 19:28:57 nicolas-Lemur kernel: [ 9239.931935]  do_init_module+0x5f/0x200
            Nov 20 19:28:57 nicolas-Lemur kernel: [ 9239.931939]  load_module+0x190b/0x1c70
            Nov 20 19:28:57 nicolas-Lemur kernel: [ 9239.931942]  ? __symbol_put+0x60/0x60
            Nov 20 19:28:57 nicolas-Lemur kernel: [ 9239.931945]  ? ima_post_read_file+0x7e/0xa0
            Nov 20 19:28:57 nicolas-Lemur kernel: [ 9239.931947]  ? security_kernel_post_read_file+0x6b/0x80
            Nov 20 19:28:57 nicolas-Lemur kernel: [ 9239.931951]  SYSC_finit_module+0xdf/0x110
            Nov 20 19:28:57 nicolas-Lemur kernel: [ 9239.931954]  SyS_finit_module+0xe/0x10
            Nov 20 19:28:57 nicolas-Lemur kernel: [ 9239.931957]  entry_SYSCALL_64_fastpath+0x1e/0xad
            Nov 20 19:28:57 nicolas-Lemur kernel: [ 9239.931959] RIP: 0033:0x7f31c65d59f9
            Nov 20 19:28:57 nicolas-Lemur kernel: [ 9239.931960] RSP: 002b:00007fff5dd93d18 EFLAGS: 00000246 ORIG_RAX: 0000000000000139
            Nov 20 19:28:57 nicolas-Lemur kernel: [ 9239.931963] RAX: ffffffffffffffda RBX: 000055b4ff17da70 RCX: 00007f31c65d59f9
            Nov 20 19:28:57 nicolas-Lemur kernel: [ 9239.931964] RDX: 0000000000000000 RSI: 000055b4fd57df8b RDI: 0000000000000003
            Nov 20 19:28:57 nicolas-Lemur kernel: [ 9239.931965] RBP: 00007f31c6894b00 R08: 0000000000000000 R09: 00007f31c6896ea0
            Nov 20 19:28:57 nicolas-Lemur kernel: [ 9239.931966] R10: 0000000000000003 R11: 0000000000000246 R12: 00007f31c6894b58
            Nov 20 19:28:57 nicolas-Lemur kernel: [ 9239.931967] R13: 00007f31c6894b58 R14: 000000000000270f R15: 0000000000001010
            Nov 20 19:28:57 nicolas-Lemur kernel: [ 9239.931969] ---[ end trace f46b3484ca86724e ]---


Slide page 45
------------

module code

    #include <linux/module.h>
    #include <linux/kernel.h>
    #include <linux/init.h>
    #include <linux/gfp.h>
    #include <linux/slab.h>

    #define PRINT_PREF "[SLAB_TEST]: "

    struct my_struct {
        int int_param;
        long long_param;
    };

    static int __init my_mod_init(void)
    {
        int ret = 0;
        struct my_struct *ptr1, *ptr2;
        struct kmem_cache *my_cache;

        printk(PRINT_PREF " Entering module.¥n");

        my_cache = kmem_cache_create("pierre-cache", sizeof(struct my_struct), 0, 0, NULL);

        if(!my_cache)
	        return -1;
        ptr1=kmem_cache_alloc(my_cache, GFP_KERNEL);
        if(!ptr1){
	        ret = -ENOMEM;
	        goto destroy_cache;
        }

        ptr2=kmem_cache_alloc(my_cache, GFP_KERNEL);
        if(!ptr2){
	        ret = -ENOMEM;
	        goto freeptr1;
        }

        ptr1->int_param=42;
        ptr1->long_param=42;
        ptr2->int_param=43;
        ptr2->long_param=43;

        printk(PRINT_PREF "ptr1 = {%d, %1d}; ptr2={%d,%1d}¥n", ptr1->int_param,
	        ptr1->long_param, ptr2->int_param, ptr2->long_param);

        kmem_cache_free(my_cache, ptr2);

        freeptr1:
	        kmem_cache_free(my_cache, ptr1);

        destroy_cache:
	        kmem_cache_destroy(my_cache);

        return ret;
    }

    static void __exit my_mod_exit(void)
    {
        printk(PRINT_PREF "Exiting module.¥n");
    }

    module_init(my_mod_init);
    module_exit(my_mod_exit);

    MODULE_LICENSE("GPL");

       

out of printk()

        
        Nov 20 19:58:50 nicolas-Lemur kernel: [11032.424435] [SLAB_TEST]:  Entering module.¥n
        Nov 20 20:02:07 nicolas-Lemur kernel: [11032.424448] [SLAB_TEST]: ptr1 = {42, 42}; ptr2={43,43}¥n
        
        
        

Slide page 51
-------------


module code


    #include <linux/module.h>
    #include <linux/kernel.h>
    #include <linux/init.h>
    #include <linux/gfp.h>
    #include <linux/slab.h>
    #include <linux/highmem.h>

    #define PRINT_PREF "[HIGHMEM]: "
    #define INTS_IN_PAGE (PAGE_SIZE/sizeof(int))

    static int __init my_mod_init(void)
    {
        struct page *my_page;
        void *my_ptr;
        int i, *int_array;

        printk(PRINT_PREF " Entering module.¥n");

        my_page = alloc_page(GFP_HIGHUSER);
        if(!my_page)
            return -1;

        my_ptr = kmap(my_page);
        int_array = (int *)my_ptr;

        for (i = 0; i <INTS_IN_PAGE; i++)
        {
            int_array[i] = i;
            printk(PRINT_PREF "array[%d] = %d¥n", i, int_array[i]);
        }

        kunmap(my_page);
        __free_pages(my_page, 0);

        return 0;
    }

    static void __exit my_mod_exit(void)
    {
        printk(PRINT_PREF "Exiting module.¥n");
    }

    module_init(my_mod_init);
    module_exit(my_mod_exit);




out of printk()


            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089535] [HIGHMEM]:  Entering module.¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089538] [HIGHMEM]: array[0] = 0¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089540] [HIGHMEM]: array[1] = 1¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089541] [HIGHMEM]: array[2] = 2¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089543] [HIGHMEM]: array[3] = 3¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089544] [HIGHMEM]: array[4] = 4¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089545] [HIGHMEM]: array[5] = 5¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089546] [HIGHMEM]: array[6] = 6¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089547] [HIGHMEM]: array[7] = 7¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089548] [HIGHMEM]: array[8] = 8¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089550] [HIGHMEM]: array[9] = 9¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089551] [HIGHMEM]: array[10] = 10¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089552] [HIGHMEM]: array[11] = 11¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089554] [HIGHMEM]: array[12] = 12¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089555] [HIGHMEM]: array[13] = 13¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089556] [HIGHMEM]: array[14] = 14¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089557] [HIGHMEM]: array[15] = 15¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089558] [HIGHMEM]: array[16] = 16¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089560] [HIGHMEM]: array[17] = 17¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089561] [HIGHMEM]: array[18] = 18¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089562] [HIGHMEM]: array[19] = 19¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089563] [HIGHMEM]: array[20] = 20¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089564] [HIGHMEM]: array[21] = 21¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089566] [HIGHMEM]: array[22] = 22¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089567] [HIGHMEM]: array[23] = 23¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089568] [HIGHMEM]: array[24] = 24¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089569] [HIGHMEM]: array[25] = 25¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089571] [HIGHMEM]: array[26] = 26¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089572] [HIGHMEM]: array[27] = 27¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089573] [HIGHMEM]: array[28] = 28¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089574] [HIGHMEM]: array[29] = 29¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089576] [HIGHMEM]: array[30] = 30¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089577] [HIGHMEM]: array[31] = 31¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089578] [HIGHMEM]: array[32] = 32¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089580] [HIGHMEM]: array[33] = 33¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089581] [HIGHMEM]: array[34] = 34¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089582] [HIGHMEM]: array[35] = 35¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089583] [HIGHMEM]: array[36] = 36¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089585] [HIGHMEM]: array[37] = 37¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089586] [HIGHMEM]: array[38] = 38¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089587] [HIGHMEM]: array[39] = 39¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089588] [HIGHMEM]: array[40] = 40¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089590] [HIGHMEM]: array[41] = 41¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089591] [HIGHMEM]: array[42] = 42¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089592] [HIGHMEM]: array[43] = 43¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089593] [HIGHMEM]: array[44] = 44¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089595] [HIGHMEM]: array[45] = 45¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089596] [HIGHMEM]: array[46] = 46¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089597] [HIGHMEM]: array[47] = 47¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089598] [HIGHMEM]: array[48] = 48¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089600] [HIGHMEM]: array[49] = 49¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089601] [HIGHMEM]: array[50] = 50¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089602] [HIGHMEM]: array[51] = 51¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089603] [HIGHMEM]: array[52] = 52¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089604] [HIGHMEM]: array[53] = 53¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089606] [HIGHMEM]: array[54] = 54¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089607] [HIGHMEM]: array[55] = 55¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089608] [HIGHMEM]: array[56] = 56¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089610] [HIGHMEM]: array[57] = 57¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089611] [HIGHMEM]: array[58] = 58¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089612] [HIGHMEM]: array[59] = 59¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089613] [HIGHMEM]: array[60] = 60¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089615] [HIGHMEM]: array[61] = 61¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089616] [HIGHMEM]: array[62] = 62¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089617] [HIGHMEM]: array[63] = 63¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089618] [HIGHMEM]: array[64] = 64¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089620] [HIGHMEM]: array[65] = 65¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089621] [HIGHMEM]: array[66] = 66¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089622] [HIGHMEM]: array[67] = 67¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089623] [HIGHMEM]: array[68] = 68¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089624] [HIGHMEM]: array[69] = 69¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089626] [HIGHMEM]: array[70] = 70¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089627] [HIGHMEM]: array[71] = 71¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089628] [HIGHMEM]: array[72] = 72¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089629] [HIGHMEM]: array[73] = 73¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089631] [HIGHMEM]: array[74] = 74¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089632] [HIGHMEM]: array[75] = 75¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089633] [HIGHMEM]: array[76] = 76¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089635] [HIGHMEM]: array[77] = 77¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089636] [HIGHMEM]: array[78] = 78¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089637] [HIGHMEM]: array[79] = 79¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089639] [HIGHMEM]: array[80] = 80¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089640] [HIGHMEM]: array[81] = 81¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089641] [HIGHMEM]: array[82] = 82¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089642] [HIGHMEM]: array[83] = 83¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089644] [HIGHMEM]: array[84] = 84¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089645] [HIGHMEM]: array[85] = 85¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089646] [HIGHMEM]: array[86] = 86¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089648] [HIGHMEM]: array[87] = 87¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089649] [HIGHMEM]: array[88] = 88¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089650] [HIGHMEM]: array[89] = 89¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089651] [HIGHMEM]: array[90] = 90¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089653] [HIGHMEM]: array[91] = 91¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089654] [HIGHMEM]: array[92] = 92¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089656] [HIGHMEM]: array[93] = 93¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089657] [HIGHMEM]: array[94] = 94¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089658] [HIGHMEM]: array[95] = 95¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089660] [HIGHMEM]: array[96] = 96¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089661] [HIGHMEM]: array[97] = 97¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089663] [HIGHMEM]: array[98] = 98¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089664] [HIGHMEM]: array[99] = 99¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089665] [HIGHMEM]: array[100] = 100¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089667] [HIGHMEM]: array[101] = 101¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089668] [HIGHMEM]: array[102] = 102¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089670] [HIGHMEM]: array[103] = 103¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089671] [HIGHMEM]: array[104] = 104¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089673] [HIGHMEM]: array[105] = 105¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089674] [HIGHMEM]: array[106] = 106¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089676] [HIGHMEM]: array[107] = 107¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089677] [HIGHMEM]: array[108] = 108¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089679] [HIGHMEM]: array[109] = 109¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089680] [HIGHMEM]: array[110] = 110¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089682] [HIGHMEM]: array[111] = 111¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089683] [HIGHMEM]: array[112] = 112¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089684] [HIGHMEM]: array[113] = 113¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089686] [HIGHMEM]: array[114] = 114¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089687] [HIGHMEM]: array[115] = 115¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089689] [HIGHMEM]: array[116] = 116¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089690] [HIGHMEM]: array[117] = 117¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089691] [HIGHMEM]: array[118] = 118¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089693] [HIGHMEM]: array[119] = 119¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089694] [HIGHMEM]: array[120] = 120¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089696] [HIGHMEM]: array[121] = 121¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089697] [HIGHMEM]: array[122] = 122¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089698] [HIGHMEM]: array[123] = 123¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089700] [HIGHMEM]: array[124] = 124¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089701] [HIGHMEM]: array[125] = 125¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089702] [HIGHMEM]: array[126] = 126¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089704] [HIGHMEM]: array[127] = 127¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089705] [HIGHMEM]: array[128] = 128¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089706] [HIGHMEM]: array[129] = 129¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089707] [HIGHMEM]: array[130] = 130¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089709] [HIGHMEM]: array[131] = 131¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089710] [HIGHMEM]: array[132] = 132¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089711] [HIGHMEM]: array[133] = 133¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089712] [HIGHMEM]: array[134] = 134¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089714] [HIGHMEM]: array[135] = 135¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089715] [HIGHMEM]: array[136] = 136¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089716] [HIGHMEM]: array[137] = 137¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089717] [HIGHMEM]: array[138] = 138¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089719] [HIGHMEM]: array[139] = 139¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089720] [HIGHMEM]: array[140] = 140¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089721] [HIGHMEM]: array[141] = 141¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089723] [HIGHMEM]: array[142] = 142¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089724] [HIGHMEM]: array[143] = 143¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089725] [HIGHMEM]: array[144] = 144¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089726] [HIGHMEM]: array[145] = 145¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089728] [HIGHMEM]: array[146] = 146¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089729] [HIGHMEM]: array[147] = 147¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089730] [HIGHMEM]: array[148] = 148¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089732] [HIGHMEM]: array[149] = 149¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089733] [HIGHMEM]: array[150] = 150¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089734] [HIGHMEM]: array[151] = 151¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089736] [HIGHMEM]: array[152] = 152¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089737] [HIGHMEM]: array[153] = 153¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089739] [HIGHMEM]: array[154] = 154¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089740] [HIGHMEM]: array[155] = 155¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089741] [HIGHMEM]: array[156] = 156¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089743] [HIGHMEM]: array[157] = 157¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089744] [HIGHMEM]: array[158] = 158¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089745] [HIGHMEM]: array[159] = 159¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089747] [HIGHMEM]: array[160] = 160¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089748] [HIGHMEM]: array[161] = 161¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089750] [HIGHMEM]: array[162] = 162¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089751] [HIGHMEM]: array[163] = 163¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089752] [HIGHMEM]: array[164] = 164¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089754] [HIGHMEM]: array[165] = 165¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089755] [HIGHMEM]: array[166] = 166¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089756] [HIGHMEM]: array[167] = 167¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089758] [HIGHMEM]: array[168] = 168¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089759] [HIGHMEM]: array[169] = 169¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089760] [HIGHMEM]: array[170] = 170¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089762] [HIGHMEM]: array[171] = 171¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089763] [HIGHMEM]: array[172] = 172¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089764] [HIGHMEM]: array[173] = 173¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089766] [HIGHMEM]: array[174] = 174¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089767] [HIGHMEM]: array[175] = 175¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089768] [HIGHMEM]: array[176] = 176¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089770] [HIGHMEM]: array[177] = 177¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089771] [HIGHMEM]: array[178] = 178¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089772] [HIGHMEM]: array[179] = 179¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089774] [HIGHMEM]: array[180] = 180¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089775] [HIGHMEM]: array[181] = 181¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089777] [HIGHMEM]: array[182] = 182¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089778] [HIGHMEM]: array[183] = 183¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089780] [HIGHMEM]: array[184] = 184¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089781] [HIGHMEM]: array[185] = 185¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089782] [HIGHMEM]: array[186] = 186¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089784] [HIGHMEM]: array[187] = 187¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089785] [HIGHMEM]: array[188] = 188¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089786] [HIGHMEM]: array[189] = 189¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089788] [HIGHMEM]: array[190] = 190¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089789] [HIGHMEM]: array[191] = 191¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089790] [HIGHMEM]: array[192] = 192¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089792] [HIGHMEM]: array[193] = 193¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089793] [HIGHMEM]: array[194] = 194¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089795] [HIGHMEM]: array[195] = 195¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089796] [HIGHMEM]: array[196] = 196¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089798] [HIGHMEM]: array[197] = 197¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089799] [HIGHMEM]: array[198] = 198¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089800] [HIGHMEM]: array[199] = 199¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089802] [HIGHMEM]: array[200] = 200¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089803] [HIGHMEM]: array[201] = 201¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089804] [HIGHMEM]: array[202] = 202¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089806] [HIGHMEM]: array[203] = 203¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089807] [HIGHMEM]: array[204] = 204¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089808] [HIGHMEM]: array[205] = 205¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089810] [HIGHMEM]: array[206] = 206¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089811] [HIGHMEM]: array[207] = 207¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089812] [HIGHMEM]: array[208] = 208¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089814] [HIGHMEM]: array[209] = 209¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089815] [HIGHMEM]: array[210] = 210¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089816] [HIGHMEM]: array[211] = 211¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089818] [HIGHMEM]: array[212] = 212¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089819] [HIGHMEM]: array[213] = 213¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089820] [HIGHMEM]: array[214] = 214¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089821] [HIGHMEM]: array[215] = 215¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089823] [HIGHMEM]: array[216] = 216¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089824] [HIGHMEM]: array[217] = 217¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089825] [HIGHMEM]: array[218] = 218¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089826] [HIGHMEM]: array[219] = 219¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089828] [HIGHMEM]: array[220] = 220¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089829] [HIGHMEM]: array[221] = 221¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089830] [HIGHMEM]: array[222] = 222¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089831] [HIGHMEM]: array[223] = 223¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089833] [HIGHMEM]: array[224] = 224¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089834] [HIGHMEM]: array[225] = 225¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089835] [HIGHMEM]: array[226] = 226¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089836] [HIGHMEM]: array[227] = 227¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089838] [HIGHMEM]: array[228] = 228¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089839] [HIGHMEM]: array[229] = 229¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089840] [HIGHMEM]: array[230] = 230¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089842] [HIGHMEM]: array[231] = 231¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089843] [HIGHMEM]: array[232] = 232¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089844] [HIGHMEM]: array[233] = 233¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089845] [HIGHMEM]: array[234] = 234¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089847] [HIGHMEM]: array[235] = 235¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089848] [HIGHMEM]: array[236] = 236¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089849] [HIGHMEM]: array[237] = 237¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089850] [HIGHMEM]: array[238] = 238¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089852] [HIGHMEM]: array[239] = 239¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089853] [HIGHMEM]: array[240] = 240¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089854] [HIGHMEM]: array[241] = 241¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089856] [HIGHMEM]: array[242] = 242¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089857] [HIGHMEM]: array[243] = 243¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089858] [HIGHMEM]: array[244] = 244¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089860] [HIGHMEM]: array[245] = 245¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089861] [HIGHMEM]: array[246] = 246¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089862] [HIGHMEM]: array[247] = 247¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089864] [HIGHMEM]: array[248] = 248¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089865] [HIGHMEM]: array[249] = 249¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089866] [HIGHMEM]: array[250] = 250¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089868] [HIGHMEM]: array[251] = 251¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089869] [HIGHMEM]: array[252] = 252¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089870] [HIGHMEM]: array[253] = 253¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089871] [HIGHMEM]: array[254] = 254¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089872] [HIGHMEM]: array[255] = 255¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089873] [HIGHMEM]: array[256] = 256¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089875] [HIGHMEM]: array[257] = 257¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089876] [HIGHMEM]: array[258] = 258¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089877] [HIGHMEM]: array[259] = 259¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089878] [HIGHMEM]: array[260] = 260¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089880] [HIGHMEM]: array[261] = 261¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089881] [HIGHMEM]: array[262] = 262¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089882] [HIGHMEM]: array[263] = 263¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089883] [HIGHMEM]: array[264] = 264¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089884] [HIGHMEM]: array[265] = 265¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089886] [HIGHMEM]: array[266] = 266¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089887] [HIGHMEM]: array[267] = 267¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089888] [HIGHMEM]: array[268] = 268¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089889] [HIGHMEM]: array[269] = 269¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089890] [HIGHMEM]: array[270] = 270¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089892] [HIGHMEM]: array[271] = 271¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089893] [HIGHMEM]: array[272] = 272¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089894] [HIGHMEM]: array[273] = 273¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089895] [HIGHMEM]: array[274] = 274¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089897] [HIGHMEM]: array[275] = 275¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089898] [HIGHMEM]: array[276] = 276¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089899] [HIGHMEM]: array[277] = 277¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089900] [HIGHMEM]: array[278] = 278¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089901] [HIGHMEM]: array[279] = 279¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089902] [HIGHMEM]: array[280] = 280¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089904] [HIGHMEM]: array[281] = 281¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089905] [HIGHMEM]: array[282] = 282¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089906] [HIGHMEM]: array[283] = 283¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089908] [HIGHMEM]: array[284] = 284¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089909] [HIGHMEM]: array[285] = 285¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089910] [HIGHMEM]: array[286] = 286¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089911] [HIGHMEM]: array[287] = 287¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089913] [HIGHMEM]: array[288] = 288¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089914] [HIGHMEM]: array[289] = 289¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089915] [HIGHMEM]: array[290] = 290¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089916] [HIGHMEM]: array[291] = 291¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089918] [HIGHMEM]: array[292] = 292¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089919] [HIGHMEM]: array[293] = 293¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089920] [HIGHMEM]: array[294] = 294¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089922] [HIGHMEM]: array[295] = 295¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089923] [HIGHMEM]: array[296] = 296¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089924] [HIGHMEM]: array[297] = 297¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089926] [HIGHMEM]: array[298] = 298¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089927] [HIGHMEM]: array[299] = 299¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089929] [HIGHMEM]: array[300] = 300¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089930] [HIGHMEM]: array[301] = 301¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089931] [HIGHMEM]: array[302] = 302¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089933] [HIGHMEM]: array[303] = 303¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089934] [HIGHMEM]: array[304] = 304¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089935] [HIGHMEM]: array[305] = 305¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089937] [HIGHMEM]: array[306] = 306¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089938] [HIGHMEM]: array[307] = 307¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089940] [HIGHMEM]: array[308] = 308¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089941] [HIGHMEM]: array[309] = 309¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089942] [HIGHMEM]: array[310] = 310¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089944] [HIGHMEM]: array[311] = 311¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089945] [HIGHMEM]: array[312] = 312¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089947] [HIGHMEM]: array[313] = 313¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089948] [HIGHMEM]: array[314] = 314¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089949] [HIGHMEM]: array[315] = 315¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089950] [HIGHMEM]: array[316] = 316¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089952] [HIGHMEM]: array[317] = 317¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089953] [HIGHMEM]: array[318] = 318¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089954] [HIGHMEM]: array[319] = 319¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089956] [HIGHMEM]: array[320] = 320¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089957] [HIGHMEM]: array[321] = 321¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089959] [HIGHMEM]: array[322] = 322¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089960] [HIGHMEM]: array[323] = 323¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089961] [HIGHMEM]: array[324] = 324¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089963] [HIGHMEM]: array[325] = 325¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089964] [HIGHMEM]: array[326] = 326¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089966] [HIGHMEM]: array[327] = 327¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089967] [HIGHMEM]: array[328] = 328¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089968] [HIGHMEM]: array[329] = 329¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089970] [HIGHMEM]: array[330] = 330¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089971] [HIGHMEM]: array[331] = 331¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089973] [HIGHMEM]: array[332] = 332¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089974] [HIGHMEM]: array[333] = 333¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089975] [HIGHMEM]: array[334] = 334¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089977] [HIGHMEM]: array[335] = 335¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089978] [HIGHMEM]: array[336] = 336¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089980] [HIGHMEM]: array[337] = 337¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089981] [HIGHMEM]: array[338] = 338¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089982] [HIGHMEM]: array[339] = 339¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089984] [HIGHMEM]: array[340] = 340¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089985] [HIGHMEM]: array[341] = 341¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089987] [HIGHMEM]: array[342] = 342¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089988] [HIGHMEM]: array[343] = 343¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089989] [HIGHMEM]: array[344] = 344¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089991] [HIGHMEM]: array[345] = 345¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089992] [HIGHMEM]: array[346] = 346¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089994] [HIGHMEM]: array[347] = 347¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089995] [HIGHMEM]: array[348] = 348¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089996] [HIGHMEM]: array[349] = 349¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089998] [HIGHMEM]: array[350] = 350¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.089999] [HIGHMEM]: array[351] = 351¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090000] [HIGHMEM]: array[352] = 352¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090002] [HIGHMEM]: array[353] = 353¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090003] [HIGHMEM]: array[354] = 354¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090005] [HIGHMEM]: array[355] = 355¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090006] [HIGHMEM]: array[356] = 356¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090007] [HIGHMEM]: array[357] = 357¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090009] [HIGHMEM]: array[358] = 358¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090010] [HIGHMEM]: array[359] = 359¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090011] [HIGHMEM]: array[360] = 360¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090013] [HIGHMEM]: array[361] = 361¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090014] [HIGHMEM]: array[362] = 362¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090016] [HIGHMEM]: array[363] = 363¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090017] [HIGHMEM]: array[364] = 364¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090019] [HIGHMEM]: array[365] = 365¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090020] [HIGHMEM]: array[366] = 366¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090021] [HIGHMEM]: array[367] = 367¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090022] [HIGHMEM]: array[368] = 368¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090024] [HIGHMEM]: array[369] = 369¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090025] [HIGHMEM]: array[370] = 370¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090027] [HIGHMEM]: array[371] = 371¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090028] [HIGHMEM]: array[372] = 372¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090029] [HIGHMEM]: array[373] = 373¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090031] [HIGHMEM]: array[374] = 374¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090032] [HIGHMEM]: array[375] = 375¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090034] [HIGHMEM]: array[376] = 376¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090035] [HIGHMEM]: array[377] = 377¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090036] [HIGHMEM]: array[378] = 378¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090038] [HIGHMEM]: array[379] = 379¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090039] [HIGHMEM]: array[380] = 380¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090041] [HIGHMEM]: array[381] = 381¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090042] [HIGHMEM]: array[382] = 382¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090044] [HIGHMEM]: array[383] = 383¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090045] [HIGHMEM]: array[384] = 384¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090046] [HIGHMEM]: array[385] = 385¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090048] [HIGHMEM]: array[386] = 386¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090049] [HIGHMEM]: array[387] = 387¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090051] [HIGHMEM]: array[388] = 388¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090052] [HIGHMEM]: array[389] = 389¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090053] [HIGHMEM]: array[390] = 390¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090055] [HIGHMEM]: array[391] = 391¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090056] [HIGHMEM]: array[392] = 392¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090058] [HIGHMEM]: array[393] = 393¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090059] [HIGHMEM]: array[394] = 394¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090060] [HIGHMEM]: array[395] = 395¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090061] [HIGHMEM]: array[396] = 396¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090063] [HIGHMEM]: array[397] = 397¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090064] [HIGHMEM]: array[398] = 398¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090066] [HIGHMEM]: array[399] = 399¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090067] [HIGHMEM]: array[400] = 400¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090068] [HIGHMEM]: array[401] = 401¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090069] [HIGHMEM]: array[402] = 402¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090071] [HIGHMEM]: array[403] = 403¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090072] [HIGHMEM]: array[404] = 404¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090073] [HIGHMEM]: array[405] = 405¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090074] [HIGHMEM]: array[406] = 406¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090076] [HIGHMEM]: array[407] = 407¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090077] [HIGHMEM]: array[408] = 408¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090079] [HIGHMEM]: array[409] = 409¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090080] [HIGHMEM]: array[410] = 410¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090081] [HIGHMEM]: array[411] = 411¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090082] [HIGHMEM]: array[412] = 412¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090084] [HIGHMEM]: array[413] = 413¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090085] [HIGHMEM]: array[414] = 414¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090086] [HIGHMEM]: array[415] = 415¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090088] [HIGHMEM]: array[416] = 416¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090089] [HIGHMEM]: array[417] = 417¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090090] [HIGHMEM]: array[418] = 418¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090092] [HIGHMEM]: array[419] = 419¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090093] [HIGHMEM]: array[420] = 420¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090094] [HIGHMEM]: array[421] = 421¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090096] [HIGHMEM]: array[422] = 422¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090097] [HIGHMEM]: array[423] = 423¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090098] [HIGHMEM]: array[424] = 424¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090100] [HIGHMEM]: array[425] = 425¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090101] [HIGHMEM]: array[426] = 426¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090102] [HIGHMEM]: array[427] = 427¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090104] [HIGHMEM]: array[428] = 428¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090105] [HIGHMEM]: array[429] = 429¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090106] [HIGHMEM]: array[430] = 430¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090108] [HIGHMEM]: array[431] = 431¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090109] [HIGHMEM]: array[432] = 432¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090111] [HIGHMEM]: array[433] = 433¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090112] [HIGHMEM]: array[434] = 434¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090113] [HIGHMEM]: array[435] = 435¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090114] [HIGHMEM]: array[436] = 436¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090116] [HIGHMEM]: array[437] = 437¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090117] [HIGHMEM]: array[438] = 438¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090118] [HIGHMEM]: array[439] = 439¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090120] [HIGHMEM]: array[440] = 440¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090121] [HIGHMEM]: array[441] = 441¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090122] [HIGHMEM]: array[442] = 442¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090124] [HIGHMEM]: array[443] = 443¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090125] [HIGHMEM]: array[444] = 444¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090126] [HIGHMEM]: array[445] = 445¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090127] [HIGHMEM]: array[446] = 446¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090129] [HIGHMEM]: array[447] = 447¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090130] [HIGHMEM]: array[448] = 448¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090132] [HIGHMEM]: array[449] = 449¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090133] [HIGHMEM]: array[450] = 450¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090134] [HIGHMEM]: array[451] = 451¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090136] [HIGHMEM]: array[452] = 452¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090137] [HIGHMEM]: array[453] = 453¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090138] [HIGHMEM]: array[454] = 454¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090140] [HIGHMEM]: array[455] = 455¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090141] [HIGHMEM]: array[456] = 456¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090143] [HIGHMEM]: array[457] = 457¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090144] [HIGHMEM]: array[458] = 458¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090145] [HIGHMEM]: array[459] = 459¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090146] [HIGHMEM]: array[460] = 460¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090148] [HIGHMEM]: array[461] = 461¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090149] [HIGHMEM]: array[462] = 462¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090150] [HIGHMEM]: array[463] = 463¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090152] [HIGHMEM]: array[464] = 464¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090153] [HIGHMEM]: array[465] = 465¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090154] [HIGHMEM]: array[466] = 466¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090156] [HIGHMEM]: array[467] = 467¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090157] [HIGHMEM]: array[468] = 468¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090158] [HIGHMEM]: array[469] = 469¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090159] [HIGHMEM]: array[470] = 470¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090161] [HIGHMEM]: array[471] = 471¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090162] [HIGHMEM]: array[472] = 472¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090163] [HIGHMEM]: array[473] = 473¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090165] [HIGHMEM]: array[474] = 474¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090166] [HIGHMEM]: array[475] = 475¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090168] [HIGHMEM]: array[476] = 476¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090169] [HIGHMEM]: array[477] = 477¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090170] [HIGHMEM]: array[478] = 478¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090171] [HIGHMEM]: array[479] = 479¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090173] [HIGHMEM]: array[480] = 480¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090174] [HIGHMEM]: array[481] = 481¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090175] [HIGHMEM]: array[482] = 482¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090177] [HIGHMEM]: array[483] = 483¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090178] [HIGHMEM]: array[484] = 484¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090179] [HIGHMEM]: array[485] = 485¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090180] [HIGHMEM]: array[486] = 486¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090181] [HIGHMEM]: array[487] = 487¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090182] [HIGHMEM]: array[488] = 488¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090183] [HIGHMEM]: array[489] = 489¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090184] [HIGHMEM]: array[490] = 490¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090186] [HIGHMEM]: array[491] = 491¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090187] [HIGHMEM]: array[492] = 492¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090188] [HIGHMEM]: array[493] = 493¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090189] [HIGHMEM]: array[494] = 494¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090190] [HIGHMEM]: array[495] = 495¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090191] [HIGHMEM]: array[496] = 496¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090193] [HIGHMEM]: array[497] = 497¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090194] [HIGHMEM]: array[498] = 498¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090195] [HIGHMEM]: array[499] = 499¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090196] [HIGHMEM]: array[500] = 500¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090198] [HIGHMEM]: array[501] = 501¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090199] [HIGHMEM]: array[502] = 502¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090200] [HIGHMEM]: array[503] = 503¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090201] [HIGHMEM]: array[504] = 504¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090203] [HIGHMEM]: array[505] = 505¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090204] [HIGHMEM]: array[506] = 506¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090205] [HIGHMEM]: array[507] = 507¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090206] [HIGHMEM]: array[508] = 508¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090207] [HIGHMEM]: array[509] = 509¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090208] [HIGHMEM]: array[510] = 510¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090209] [HIGHMEM]: array[511] = 511¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090211] [HIGHMEM]: array[512] = 512¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090212] [HIGHMEM]: array[513] = 513¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090213] [HIGHMEM]: array[514] = 514¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090214] [HIGHMEM]: array[515] = 515¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090215] [HIGHMEM]: array[516] = 516¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090217] [HIGHMEM]: array[517] = 517¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090218] [HIGHMEM]: array[518] = 518¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090219] [HIGHMEM]: array[519] = 519¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090220] [HIGHMEM]: array[520] = 520¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090221] [HIGHMEM]: array[521] = 521¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090223] [HIGHMEM]: array[522] = 522¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090224] [HIGHMEM]: array[523] = 523¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090225] [HIGHMEM]: array[524] = 524¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090227] [HIGHMEM]: array[525] = 525¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090228] [HIGHMEM]: array[526] = 526¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090229] [HIGHMEM]: array[527] = 527¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090230] [HIGHMEM]: array[528] = 528¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090232] [HIGHMEM]: array[529] = 529¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090233] [HIGHMEM]: array[530] = 530¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090235] [HIGHMEM]: array[531] = 531¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090236] [HIGHMEM]: array[532] = 532¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090237] [HIGHMEM]: array[533] = 533¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090239] [HIGHMEM]: array[534] = 534¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090240] [HIGHMEM]: array[535] = 535¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090241] [HIGHMEM]: array[536] = 536¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090243] [HIGHMEM]: array[537] = 537¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090244] [HIGHMEM]: array[538] = 538¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090246] [HIGHMEM]: array[539] = 539¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090247] [HIGHMEM]: array[540] = 540¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090248] [HIGHMEM]: array[541] = 541¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090250] [HIGHMEM]: array[542] = 542¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090251] [HIGHMEM]: array[543] = 543¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090253] [HIGHMEM]: array[544] = 544¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090254] [HIGHMEM]: array[545] = 545¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090256] [HIGHMEM]: array[546] = 546¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090257] [HIGHMEM]: array[547] = 547¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090258] [HIGHMEM]: array[548] = 548¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090259] [HIGHMEM]: array[549] = 549¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090261] [HIGHMEM]: array[550] = 550¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090262] [HIGHMEM]: array[551] = 551¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090264] [HIGHMEM]: array[552] = 552¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090265] [HIGHMEM]: array[553] = 553¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090266] [HIGHMEM]: array[554] = 554¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090268] [HIGHMEM]: array[555] = 555¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090269] [HIGHMEM]: array[556] = 556¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090270] [HIGHMEM]: array[557] = 557¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090271] [HIGHMEM]: array[558] = 558¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090272] [HIGHMEM]: array[559] = 559¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090274] [HIGHMEM]: array[560] = 560¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090275] [HIGHMEM]: array[561] = 561¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090276] [HIGHMEM]: array[562] = 562¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090277] [HIGHMEM]: array[563] = 563¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090278] [HIGHMEM]: array[564] = 564¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090280] [HIGHMEM]: array[565] = 565¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090281] [HIGHMEM]: array[566] = 566¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090282] [HIGHMEM]: array[567] = 567¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090283] [HIGHMEM]: array[568] = 568¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090284] [HIGHMEM]: array[569] = 569¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090286] [HIGHMEM]: array[570] = 570¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090287] [HIGHMEM]: array[571] = 571¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090288] [HIGHMEM]: array[572] = 572¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090289] [HIGHMEM]: array[573] = 573¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090291] [HIGHMEM]: array[574] = 574¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090292] [HIGHMEM]: array[575] = 575¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090293] [HIGHMEM]: array[576] = 576¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090295] [HIGHMEM]: array[577] = 577¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090296] [HIGHMEM]: array[578] = 578¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090297] [HIGHMEM]: array[579] = 579¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090298] [HIGHMEM]: array[580] = 580¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090299] [HIGHMEM]: array[581] = 581¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090301] [HIGHMEM]: array[582] = 582¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090302] [HIGHMEM]: array[583] = 583¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090303] [HIGHMEM]: array[584] = 584¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090305] [HIGHMEM]: array[585] = 585¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090306] [HIGHMEM]: array[586] = 586¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090307] [HIGHMEM]: array[587] = 587¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090308] [HIGHMEM]: array[588] = 588¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090309] [HIGHMEM]: array[589] = 589¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090310] [HIGHMEM]: array[590] = 590¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090311] [HIGHMEM]: array[591] = 591¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090312] [HIGHMEM]: array[592] = 592¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090313] [HIGHMEM]: array[593] = 593¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090314] [HIGHMEM]: array[594] = 594¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090315] [HIGHMEM]: array[595] = 595¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090316] [HIGHMEM]: array[596] = 596¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090316] [HIGHMEM]: array[597] = 597¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090317] [HIGHMEM]: array[598] = 598¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090318] [HIGHMEM]: array[599] = 599¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090319] [HIGHMEM]: array[600] = 600¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090320] [HIGHMEM]: array[601] = 601¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090321] [HIGHMEM]: array[602] = 602¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090322] [HIGHMEM]: array[603] = 603¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090322] [HIGHMEM]: array[604] = 604¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090323] [HIGHMEM]: array[605] = 605¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090324] [HIGHMEM]: array[606] = 606¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090325] [HIGHMEM]: array[607] = 607¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090326] [HIGHMEM]: array[608] = 608¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090327] [HIGHMEM]: array[609] = 609¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090328] [HIGHMEM]: array[610] = 610¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090328] [HIGHMEM]: array[611] = 611¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090329] [HIGHMEM]: array[612] = 612¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090330] [HIGHMEM]: array[613] = 613¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090331] [HIGHMEM]: array[614] = 614¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090332] [HIGHMEM]: array[615] = 615¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090333] [HIGHMEM]: array[616] = 616¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090334] [HIGHMEM]: array[617] = 617¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090334] [HIGHMEM]: array[618] = 618¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090335] [HIGHMEM]: array[619] = 619¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090336] [HIGHMEM]: array[620] = 620¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090337] [HIGHMEM]: array[621] = 621¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090338] [HIGHMEM]: array[622] = 622¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090339] [HIGHMEM]: array[623] = 623¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090340] [HIGHMEM]: array[624] = 624¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090340] [HIGHMEM]: array[625] = 625¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090341] [HIGHMEM]: array[626] = 626¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090342] [HIGHMEM]: array[627] = 627¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090343] [HIGHMEM]: array[628] = 628¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090344] [HIGHMEM]: array[629] = 629¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090345] [HIGHMEM]: array[630] = 630¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090346] [HIGHMEM]: array[631] = 631¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090346] [HIGHMEM]: array[632] = 632¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090347] [HIGHMEM]: array[633] = 633¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090348] [HIGHMEM]: array[634] = 634¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090349] [HIGHMEM]: array[635] = 635¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090350] [HIGHMEM]: array[636] = 636¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090351] [HIGHMEM]: array[637] = 637¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090352] [HIGHMEM]: array[638] = 638¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090352] [HIGHMEM]: array[639] = 639¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090353] [HIGHMEM]: array[640] = 640¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090354] [HIGHMEM]: array[641] = 641¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090355] [HIGHMEM]: array[642] = 642¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090356] [HIGHMEM]: array[643] = 643¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090357] [HIGHMEM]: array[644] = 644¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090358] [HIGHMEM]: array[645] = 645¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090358] [HIGHMEM]: array[646] = 646¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090359] [HIGHMEM]: array[647] = 647¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090360] [HIGHMEM]: array[648] = 648¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090361] [HIGHMEM]: array[649] = 649¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090362] [HIGHMEM]: array[650] = 650¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090363] [HIGHMEM]: array[651] = 651¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090364] [HIGHMEM]: array[652] = 652¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090364] [HIGHMEM]: array[653] = 653¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090365] [HIGHMEM]: array[654] = 654¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090366] [HIGHMEM]: array[655] = 655¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090367] [HIGHMEM]: array[656] = 656¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090368] [HIGHMEM]: array[657] = 657¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090369] [HIGHMEM]: array[658] = 658¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090369] [HIGHMEM]: array[659] = 659¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090370] [HIGHMEM]: array[660] = 660¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090371] [HIGHMEM]: array[661] = 661¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090372] [HIGHMEM]: array[662] = 662¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090373] [HIGHMEM]: array[663] = 663¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090374] [HIGHMEM]: array[664] = 664¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090375] [HIGHMEM]: array[665] = 665¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090375] [HIGHMEM]: array[666] = 666¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090376] [HIGHMEM]: array[667] = 667¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090377] [HIGHMEM]: array[668] = 668¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090378] [HIGHMEM]: array[669] = 669¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090379] [HIGHMEM]: array[670] = 670¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090380] [HIGHMEM]: array[671] = 671¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090381] [HIGHMEM]: array[672] = 672¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090381] [HIGHMEM]: array[673] = 673¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090382] [HIGHMEM]: array[674] = 674¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090383] [HIGHMEM]: array[675] = 675¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090384] [HIGHMEM]: array[676] = 676¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090385] [HIGHMEM]: array[677] = 677¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090386] [HIGHMEM]: array[678] = 678¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090387] [HIGHMEM]: array[679] = 679¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090387] [HIGHMEM]: array[680] = 680¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090388] [HIGHMEM]: array[681] = 681¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090389] [HIGHMEM]: array[682] = 682¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090390] [HIGHMEM]: array[683] = 683¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090391] [HIGHMEM]: array[684] = 684¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090392] [HIGHMEM]: array[685] = 685¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090392] [HIGHMEM]: array[686] = 686¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090393] [HIGHMEM]: array[687] = 687¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090394] [HIGHMEM]: array[688] = 688¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090395] [HIGHMEM]: array[689] = 689¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090396] [HIGHMEM]: array[690] = 690¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090397] [HIGHMEM]: array[691] = 691¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090398] [HIGHMEM]: array[692] = 692¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090398] [HIGHMEM]: array[693] = 693¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090399] [HIGHMEM]: array[694] = 694¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090400] [HIGHMEM]: array[695] = 695¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090401] [HIGHMEM]: array[696] = 696¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090402] [HIGHMEM]: array[697] = 697¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090403] [HIGHMEM]: array[698] = 698¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090404] [HIGHMEM]: array[699] = 699¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090405] [HIGHMEM]: array[700] = 700¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090405] [HIGHMEM]: array[701] = 701¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090406] [HIGHMEM]: array[702] = 702¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090407] [HIGHMEM]: array[703] = 703¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090408] [HIGHMEM]: array[704] = 704¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090409] [HIGHMEM]: array[705] = 705¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090410] [HIGHMEM]: array[706] = 706¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090411] [HIGHMEM]: array[707] = 707¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090411] [HIGHMEM]: array[708] = 708¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090412] [HIGHMEM]: array[709] = 709¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090413] [HIGHMEM]: array[710] = 710¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090414] [HIGHMEM]: array[711] = 711¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090415] [HIGHMEM]: array[712] = 712¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090416] [HIGHMEM]: array[713] = 713¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090416] [HIGHMEM]: array[714] = 714¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090417] [HIGHMEM]: array[715] = 715¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090418] [HIGHMEM]: array[716] = 716¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090419] [HIGHMEM]: array[717] = 717¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090420] [HIGHMEM]: array[718] = 718¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090421] [HIGHMEM]: array[719] = 719¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090422] [HIGHMEM]: array[720] = 720¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090423] [HIGHMEM]: array[721] = 721¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090423] [HIGHMEM]: array[722] = 722¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090424] [HIGHMEM]: array[723] = 723¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090425] [HIGHMEM]: array[724] = 724¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090426] [HIGHMEM]: array[725] = 725¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090427] [HIGHMEM]: array[726] = 726¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090428] [HIGHMEM]: array[727] = 727¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090429] [HIGHMEM]: array[728] = 728¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090429] [HIGHMEM]: array[729] = 729¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090430] [HIGHMEM]: array[730] = 730¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090431] [HIGHMEM]: array[731] = 731¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090432] [HIGHMEM]: array[732] = 732¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090433] [HIGHMEM]: array[733] = 733¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090434] [HIGHMEM]: array[734] = 734¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090434] [HIGHMEM]: array[735] = 735¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090435] [HIGHMEM]: array[736] = 736¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090436] [HIGHMEM]: array[737] = 737¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090437] [HIGHMEM]: array[738] = 738¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090438] [HIGHMEM]: array[739] = 739¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090439] [HIGHMEM]: array[740] = 740¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090440] [HIGHMEM]: array[741] = 741¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090440] [HIGHMEM]: array[742] = 742¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090441] [HIGHMEM]: array[743] = 743¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090442] [HIGHMEM]: array[744] = 744¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090443] [HIGHMEM]: array[745] = 745¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090444] [HIGHMEM]: array[746] = 746¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090445] [HIGHMEM]: array[747] = 747¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090445] [HIGHMEM]: array[748] = 748¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090446] [HIGHMEM]: array[749] = 749¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090447] [HIGHMEM]: array[750] = 750¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090448] [HIGHMEM]: array[751] = 751¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090449] [HIGHMEM]: array[752] = 752¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090450] [HIGHMEM]: array[753] = 753¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090451] [HIGHMEM]: array[754] = 754¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090451] [HIGHMEM]: array[755] = 755¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090452] [HIGHMEM]: array[756] = 756¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090453] [HIGHMEM]: array[757] = 757¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090454] [HIGHMEM]: array[758] = 758¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090455] [HIGHMEM]: array[759] = 759¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090456] [HIGHMEM]: array[760] = 760¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090457] [HIGHMEM]: array[761] = 761¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090457] [HIGHMEM]: array[762] = 762¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090458] [HIGHMEM]: array[763] = 763¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090459] [HIGHMEM]: array[764] = 764¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090460] [HIGHMEM]: array[765] = 765¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090461] [HIGHMEM]: array[766] = 766¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090462] [HIGHMEM]: array[767] = 767¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090463] [HIGHMEM]: array[768] = 768¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090463] [HIGHMEM]: array[769] = 769¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090464] [HIGHMEM]: array[770] = 770¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090465] [HIGHMEM]: array[771] = 771¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090466] [HIGHMEM]: array[772] = 772¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090467] [HIGHMEM]: array[773] = 773¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090468] [HIGHMEM]: array[774] = 774¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090469] [HIGHMEM]: array[775] = 775¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090469] [HIGHMEM]: array[776] = 776¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090470] [HIGHMEM]: array[777] = 777¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090471] [HIGHMEM]: array[778] = 778¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090472] [HIGHMEM]: array[779] = 779¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090473] [HIGHMEM]: array[780] = 780¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090474] [HIGHMEM]: array[781] = 781¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090475] [HIGHMEM]: array[782] = 782¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090475] [HIGHMEM]: array[783] = 783¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090476] [HIGHMEM]: array[784] = 784¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090477] [HIGHMEM]: array[785] = 785¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090478] [HIGHMEM]: array[786] = 786¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090479] [HIGHMEM]: array[787] = 787¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090480] [HIGHMEM]: array[788] = 788¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090481] [HIGHMEM]: array[789] = 789¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090482] [HIGHMEM]: array[790] = 790¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090482] [HIGHMEM]: array[791] = 791¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090483] [HIGHMEM]: array[792] = 792¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090484] [HIGHMEM]: array[793] = 793¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090485] [HIGHMEM]: array[794] = 794¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090486] [HIGHMEM]: array[795] = 795¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090487] [HIGHMEM]: array[796] = 796¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090487] [HIGHMEM]: array[797] = 797¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090488] [HIGHMEM]: array[798] = 798¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090489] [HIGHMEM]: array[799] = 799¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090490] [HIGHMEM]: array[800] = 800¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090491] [HIGHMEM]: array[801] = 801¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090492] [HIGHMEM]: array[802] = 802¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090493] [HIGHMEM]: array[803] = 803¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090570] [HIGHMEM]: array[804] = 804¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090572] [HIGHMEM]: array[805] = 805¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090575] [HIGHMEM]: array[806] = 806¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090581] [HIGHMEM]: array[807] = 807¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090584] [HIGHMEM]: array[808] = 808¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090586] [HIGHMEM]: array[809] = 809¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090590] [HIGHMEM]: array[810] = 810¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090592] [HIGHMEM]: array[811] = 811¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090594] [HIGHMEM]: array[812] = 812¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090603] [HIGHMEM]: array[813] = 813¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090606] [HIGHMEM]: array[814] = 814¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090609] [HIGHMEM]: array[815] = 815¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090613] [HIGHMEM]: array[816] = 816¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090615] [HIGHMEM]: array[817] = 817¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090618] [HIGHMEM]: array[818] = 818¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090621] [HIGHMEM]: array[819] = 819¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090623] [HIGHMEM]: array[820] = 820¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090626] [HIGHMEM]: array[821] = 821¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090628] [HIGHMEM]: array[822] = 822¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090630] [HIGHMEM]: array[823] = 823¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090633] [HIGHMEM]: array[824] = 824¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090635] [HIGHMEM]: array[825] = 825¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090638] [HIGHMEM]: array[826] = 826¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090641] [HIGHMEM]: array[827] = 827¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090644] [HIGHMEM]: array[828] = 828¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090646] [HIGHMEM]: array[829] = 829¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090650] [HIGHMEM]: array[830] = 830¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090653] [HIGHMEM]: array[831] = 831¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090657] [HIGHMEM]: array[832] = 832¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090659] [HIGHMEM]: array[833] = 833¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090661] [HIGHMEM]: array[834] = 834¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090664] [HIGHMEM]: array[835] = 835¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090666] [HIGHMEM]: array[836] = 836¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090669] [HIGHMEM]: array[837] = 837¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090671] [HIGHMEM]: array[838] = 838¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090673] [HIGHMEM]: array[839] = 839¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090675] [HIGHMEM]: array[840] = 840¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090677] [HIGHMEM]: array[841] = 841¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090679] [HIGHMEM]: array[842] = 842¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090683] [HIGHMEM]: array[843] = 843¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090686] [HIGHMEM]: array[844] = 844¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090689] [HIGHMEM]: array[845] = 845¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090691] [HIGHMEM]: array[846] = 846¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090693] [HIGHMEM]: array[847] = 847¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090697] [HIGHMEM]: array[848] = 848¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090699] [HIGHMEM]: array[849] = 849¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090702] [HIGHMEM]: array[850] = 850¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090706] [HIGHMEM]: array[851] = 851¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090709] [HIGHMEM]: array[852] = 852¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090713] [HIGHMEM]: array[853] = 853¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090717] [HIGHMEM]: array[854] = 854¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090721] [HIGHMEM]: array[855] = 855¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090728] [HIGHMEM]: array[856] = 856¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090730] [HIGHMEM]: array[857] = 857¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090734] [HIGHMEM]: array[858] = 858¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090737] [HIGHMEM]: array[859] = 859¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090741] [HIGHMEM]: array[860] = 860¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090743] [HIGHMEM]: array[861] = 861¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090745] [HIGHMEM]: array[862] = 862¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090747] [HIGHMEM]: array[863] = 863¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090751] [HIGHMEM]: array[864] = 864¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090753] [HIGHMEM]: array[865] = 865¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090756] [HIGHMEM]: array[866] = 866¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090760] [HIGHMEM]: array[867] = 867¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090762] [HIGHMEM]: array[868] = 868¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090766] [HIGHMEM]: array[869] = 869¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090769] [HIGHMEM]: array[870] = 870¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090773] [HIGHMEM]: array[871] = 871¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090775] [HIGHMEM]: array[872] = 872¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090778] [HIGHMEM]: array[873] = 873¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090782] [HIGHMEM]: array[874] = 874¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090785] [HIGHMEM]: array[875] = 875¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090787] [HIGHMEM]: array[876] = 876¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090790] [HIGHMEM]: array[877] = 877¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090795] [HIGHMEM]: array[878] = 878¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090798] [HIGHMEM]: array[879] = 879¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090805] [HIGHMEM]: array[880] = 880¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090808] [HIGHMEM]: array[881] = 881¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090812] [HIGHMEM]: array[882] = 882¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090815] [HIGHMEM]: array[883] = 883¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090819] [HIGHMEM]: array[884] = 884¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090821] [HIGHMEM]: array[885] = 885¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090825] [HIGHMEM]: array[886] = 886¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090828] [HIGHMEM]: array[887] = 887¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090831] [HIGHMEM]: array[888] = 888¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090834] [HIGHMEM]: array[889] = 889¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090836] [HIGHMEM]: array[890] = 890¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090838] [HIGHMEM]: array[891] = 891¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090842] [HIGHMEM]: array[892] = 892¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090844] [HIGHMEM]: array[893] = 893¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090847] [HIGHMEM]: array[894] = 894¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090850] [HIGHMEM]: array[895] = 895¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090852] [HIGHMEM]: array[896] = 896¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090854] [HIGHMEM]: array[897] = 897¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090858] [HIGHMEM]: array[898] = 898¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090861] [HIGHMEM]: array[899] = 899¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090865] [HIGHMEM]: array[900] = 900¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090867] [HIGHMEM]: array[901] = 901¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090872] [HIGHMEM]: array[902] = 902¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090875] [HIGHMEM]: array[903] = 903¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090881] [HIGHMEM]: array[904] = 904¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090884] [HIGHMEM]: array[905] = 905¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090885] [HIGHMEM]: array[906] = 906¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090886] [HIGHMEM]: array[907] = 907¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090887] [HIGHMEM]: array[908] = 908¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090888] [HIGHMEM]: array[909] = 909¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090890] [HIGHMEM]: array[910] = 910¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090891] [HIGHMEM]: array[911] = 911¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090892] [HIGHMEM]: array[912] = 912¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090893] [HIGHMEM]: array[913] = 913¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090894] [HIGHMEM]: array[914] = 914¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090895] [HIGHMEM]: array[915] = 915¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090896] [HIGHMEM]: array[916] = 916¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090898] [HIGHMEM]: array[917] = 917¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090899] [HIGHMEM]: array[918] = 918¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090900] [HIGHMEM]: array[919] = 919¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090901] [HIGHMEM]: array[920] = 920¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090902] [HIGHMEM]: array[921] = 921¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090903] [HIGHMEM]: array[922] = 922¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090904] [HIGHMEM]: array[923] = 923¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090905] [HIGHMEM]: array[924] = 924¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090907] [HIGHMEM]: array[925] = 925¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090908] [HIGHMEM]: array[926] = 926¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090909] [HIGHMEM]: array[927] = 927¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090910] [HIGHMEM]: array[928] = 928¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090911] [HIGHMEM]: array[929] = 929¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090912] [HIGHMEM]: array[930] = 930¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090913] [HIGHMEM]: array[931] = 931¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090914] [HIGHMEM]: array[932] = 932¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090915] [HIGHMEM]: array[933] = 933¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090917] [HIGHMEM]: array[934] = 934¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090918] [HIGHMEM]: array[935] = 935¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090919] [HIGHMEM]: array[936] = 936¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090920] [HIGHMEM]: array[937] = 937¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090921] [HIGHMEM]: array[938] = 938¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090922] [HIGHMEM]: array[939] = 939¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090923] [HIGHMEM]: array[940] = 940¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090924] [HIGHMEM]: array[941] = 941¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090925] [HIGHMEM]: array[942] = 942¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090927] [HIGHMEM]: array[943] = 943¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090928] [HIGHMEM]: array[944] = 944¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090929] [HIGHMEM]: array[945] = 945¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090930] [HIGHMEM]: array[946] = 946¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090932] [HIGHMEM]: array[947] = 947¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090933] [HIGHMEM]: array[948] = 948¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090934] [HIGHMEM]: array[949] = 949¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090936] [HIGHMEM]: array[950] = 950¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090937] [HIGHMEM]: array[951] = 951¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090939] [HIGHMEM]: array[952] = 952¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090941] [HIGHMEM]: array[953] = 953¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090942] [HIGHMEM]: array[954] = 954¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090943] [HIGHMEM]: array[955] = 955¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090945] [HIGHMEM]: array[956] = 956¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090949] [HIGHMEM]: array[957] = 957¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090951] [HIGHMEM]: array[958] = 958¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090952] [HIGHMEM]: array[959] = 959¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090954] [HIGHMEM]: array[960] = 960¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090955] [HIGHMEM]: array[961] = 961¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090957] [HIGHMEM]: array[962] = 962¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090958] [HIGHMEM]: array[963] = 963¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090960] [HIGHMEM]: array[964] = 964¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090961] [HIGHMEM]: array[965] = 965¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090963] [HIGHMEM]: array[966] = 966¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090964] [HIGHMEM]: array[967] = 967¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090966] [HIGHMEM]: array[968] = 968¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090967] [HIGHMEM]: array[969] = 969¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090969] [HIGHMEM]: array[970] = 970¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090970] [HIGHMEM]: array[971] = 971¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090971] [HIGHMEM]: array[972] = 972¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090973] [HIGHMEM]: array[973] = 973¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090974] [HIGHMEM]: array[974] = 974¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090976] [HIGHMEM]: array[975] = 975¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090977] [HIGHMEM]: array[976] = 976¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090979] [HIGHMEM]: array[977] = 977¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090980] [HIGHMEM]: array[978] = 978¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090982] [HIGHMEM]: array[979] = 979¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090983] [HIGHMEM]: array[980] = 980¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090985] [HIGHMEM]: array[981] = 981¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090986] [HIGHMEM]: array[982] = 982¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090988] [HIGHMEM]: array[983] = 983¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090989] [HIGHMEM]: array[984] = 984¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090990] [HIGHMEM]: array[985] = 985¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090992] [HIGHMEM]: array[986] = 986¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090993] [HIGHMEM]: array[987] = 987¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090995] [HIGHMEM]: array[988] = 988¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090996] [HIGHMEM]: array[989] = 989¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090998] [HIGHMEM]: array[990] = 990¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.090999] [HIGHMEM]: array[991] = 991¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.091001] [HIGHMEM]: array[992] = 992¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.091002] [HIGHMEM]: array[993] = 993¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.091004] [HIGHMEM]: array[994] = 994¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.091005] [HIGHMEM]: array[995] = 995¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.091006] [HIGHMEM]: array[996] = 996¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.091008] [HIGHMEM]: array[997] = 997¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.091009] [HIGHMEM]: array[998] = 998¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.091011] [HIGHMEM]: array[999] = 999¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.091013] [HIGHMEM]: array[1000] = 1000¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.091015] [HIGHMEM]: array[1001] = 1001¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.091016] [HIGHMEM]: array[1002] = 1002¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.091018] [HIGHMEM]: array[1003] = 1003¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.091022] [HIGHMEM]: array[1004] = 1004¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.091023] [HIGHMEM]: array[1005] = 1005¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.091025] [HIGHMEM]: array[1006] = 1006¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.091026] [HIGHMEM]: array[1007] = 1007¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.091028] [HIGHMEM]: array[1008] = 1008¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.091029] [HIGHMEM]: array[1009] = 1009¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.091031] [HIGHMEM]: array[1010] = 1010¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.091032] [HIGHMEM]: array[1011] = 1011¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.091034] [HIGHMEM]: array[1012] = 1012¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.091035] [HIGHMEM]: array[1013] = 1013¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.091037] [HIGHMEM]: array[1014] = 1014¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.091038] [HIGHMEM]: array[1015] = 1015¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.091040] [HIGHMEM]: array[1016] = 1016¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.091041] [HIGHMEM]: array[1017] = 1017¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.091043] [HIGHMEM]: array[1018] = 1018¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.091044] [HIGHMEM]: array[1019] = 1019¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.091045] [HIGHMEM]: array[1020] = 1020¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.091047] [HIGHMEM]: array[1021] = 1021¥n
            Nov 20 22:00:57 nicolas-Lemur kernel: [13981.091048] [HIGHMEM]: array[1022] = 1022¥n
            
            
   
Slide page 57
------------

module code


    #include <linux/module.h>
    #include <linux/kernel.h>
    #include <linux/init.h>
    #include <linux/percpu.h>
    #include <linux/kthread.h>
    #include <linux/sched.h>
    #include <linux/delay.h>
    #include <linux/smp.h>

    #define PRINT_PREF "[PERCPU]: "

    struct task_struct *thread1, *thread2, *thread3;
    DEFINE_PER_CPU(int, my_var);

    static int thread_function(void *data)
    {
	    while(!kthread_should_stop()) {
		    int cpu;
		    get_cpu_var(my_var)++;
		    cpu = smp_processor_id();
		    printk("cpu[%d] = %d¥n", cpu, get_cpu_var(my_var));
		    put_cpu_var(my_var);
		    msleep(500);
	    }
    }

    static int __init my_mod_init(void)
    {
	    int cpu;

	    printk(PRINT_PREF " Entering module.¥n");

	    for (cpu = 0; cpu <NR_CPUS; cpu++)
		    per_cpu(my_var, cpu) = 0;
	
	    wmb();

	    thread1 = kthread_run(thread_function, NULL, "percpu-thread1");
	    thread2 = kthread_run(thread_function, NULL, "percpu-thread2");
	    thread3 = kthread_run(thread_function, NULL, "percpu-thread3");

	    return 0;
    }

    static void __exit my_mod_exit(void)
    {
	    kthread_stop(thread1);
	    kthread_stop(thread2);
	    kthread_stop(thread3);
	    printk(PRINT_PREF "Exiting module.¥n");
    }

    module_init(my_mod_init);
    module_exit(my_mod_exit);

    MODULE_LICENSE("GPL");


out of printk()


    Nov 20 22:28:54 nicolas-Lemur kernel: [15658.300472] [PERCPU]:  Entering module.¥n
    Nov 20 22:28:54 nicolas-Lemur kernel: [15658.300568] cpu[2] = 1¥n
    Nov 20 22:28:54 nicolas-Lemur kernel: [15658.300784] cpu[3] = 1¥n
    Nov 20 22:28:55 nicolas-Lemur kernel: [15658.300828] cpu[3] = 2¥n
    Nov 20 22:28:55 nicolas-Lemur kernel: [15658.831872] cpu[2] = 2¥n
    Nov 20 22:28:55 nicolas-Lemur kernel: [15658.831879] cpu[1] = 1¥n
    Nov 20 22:28:55 nicolas-Lemur kernel: [15658.831907] cpu[3] = 3¥n
    Nov 20 22:28:55 nicolas-Lemur kernel: [15659.343850] cpu[2] = 3¥n
    Nov 20 22:28:55 nicolas-Lemur kernel: [15659.343854] cpu[1] = 2¥n
    Nov 20 22:28:56 nicolas-Lemur kernel: [15659.343856] cpu[3] = 4¥n
    Nov 20 22:28:56 nicolas-Lemur kernel: [15659.855794] cpu[2] = 4¥n
    Nov 20 22:28:56 nicolas-Lemur kernel: [15659.855795] cpu[0] = 1¥n
    Nov 20 22:28:56 nicolas-Lemur kernel: [15659.855803] cpu[2] = 5¥n
    Nov 20 22:28:56 nicolas-Lemur kernel: [15660.367758] cpu[3] = 5¥n
    Nov 20 22:28:56 nicolas-Lemur kernel: [15660.367769] cpu[2] = 6¥n
    Nov 20 22:28:57 nicolas-Lemur kernel: [15660.367771] cpu[0] = 2¥n
    Nov 20 22:28:57 nicolas-Lemur kernel: [15660.879670] cpu[0] = 3¥n
    Nov 20 22:28:57 nicolas-Lemur kernel: [15660.879674] cpu[3] = 6¥n
    Nov 20 22:28:57 nicolas-Lemur kernel: [15660.879683] cpu[0] = 4¥n
    Nov 20 22:28:57 nicolas-Lemur kernel: [15661.391575] cpu[3] = 7¥n
    Nov 20 22:28:57 nicolas-Lemur kernel: [15661.391633] cpu[2] = 7¥n
    Nov 20 22:28:58 nicolas-Lemur kernel: [15661.391642] cpu[2] = 8¥n
    Nov 20 22:28:58 nicolas-Lemur kernel: [15661.903583] cpu[0] = 5¥n
    Nov 20 22:28:58 nicolas-Lemur kernel: [15661.903630] cpu[2] = 9¥n
    Nov 20 22:28:58 nicolas-Lemur kernel: [15661.903635] cpu[3] = 8¥n
    Nov 20 22:28:58 nicolas-Lemur kernel: [15662.415579] cpu[2] = 10¥n
    Nov 20 22:28:58 nicolas-Lemur kernel: [15662.415581] cpu[0] = 6¥n
    Nov 20 22:28:59 nicolas-Lemur kernel: [15662.419520] cpu[3] = 9¥n
    Nov 20 22:28:59 nicolas-Lemur kernel: [15662.927479] cpu[3] = 10¥n
    Nov 20 22:28:59 nicolas-Lemur kernel: [15662.927508] cpu[0] = 7¥n
    Nov 20 22:28:59 nicolas-Lemur kernel: [15662.927510] cpu[2] = 11¥n
    Nov 20 22:28:59 nicolas-Lemur kernel: [15663.439450] cpu[2] = 12¥n
    Nov 20 22:28:59 nicolas-Lemur kernel: [15663.439455] cpu[3] = 11¥n
    Nov 20 22:29:00 nicolas-Lemur kernel: [15663.439500] cpu[3] = 12¥n
    Nov 20 22:29:00 nicolas-Lemur kernel: [15663.951399] cpu[1] = 3¥n
    Nov 20 22:29:00 nicolas-Lemur kernel: [15663.951443] cpu[2] = 13¥n
    Nov 20 22:29:00 nicolas-Lemur kernel: [15663.951447] cpu[3] = 13¥n
    Nov 20 22:29:00 nicolas-Lemur kernel: [15664.463326] cpu[2] = 14¥n
    Nov 20 22:29:00 nicolas-Lemur kernel: [15664.463334] cpu[3] = 14¥n
    Nov 20 22:29:01 nicolas-Lemur kernel: [15664.463336] cpu[1] = 4¥n
    Nov 20 22:29:01 nicolas-Lemur kernel: [15664.975252] cpu[0] = 8¥n
    Nov 20 22:29:01 nicolas-Lemur kernel: [15664.975276] cpu[3] = 15¥n
    Nov 20 22:29:01 nicolas-Lemur kernel: [15664.975278] cpu[1] = 5¥n
    Nov 20 22:29:01 nicolas-Lemur kernel: [15665.487274] cpu[3] = 16¥n
    Nov 20 22:29:01 nicolas-Lemur kernel: [15665.487276] cpu[1] = 6¥n
    Nov 20 22:29:02 nicolas-Lemur kernel: [15665.487279] cpu[0] = 9¥n
    Nov 20 22:29:02 nicolas-Lemur kernel: [15665.999224] cpu[0] = 10¥n
    Nov 20 22:29:02 nicolas-Lemur kernel: [15665.999228] cpu[3] = 17¥n
    Nov 20 22:29:02 nicolas-Lemur kernel: [15665.999230] cpu[1] = 7¥n
    Nov 20 22:29:02 nicolas-Lemur kernel: [15666.511146] cpu[0] = 11¥n
    Nov 20 22:29:02 nicolas-Lemur kernel: [15666.511153] cpu[1] = 8¥n
    Nov 20 22:29:03 nicolas-Lemur kernel: [15666.511156] cpu[3] = 18¥n
    Nov 20 22:29:03 nicolas-Lemur kernel: [15667.023089] cpu[0] = 12¥n
    Nov 20 22:29:03 nicolas-Lemur kernel: [15667.023092] cpu[1] = 9¥n
    Nov 20 22:29:03 nicolas-Lemur kernel: [15667.023095] cpu[3] = 19¥n
    Nov 20 22:29:03 nicolas-Lemur kernel: [15667.535087] cpu[0] = 13¥n
    Nov 20 22:29:03 nicolas-Lemur kernel: [15667.535102] cpu[1] = 10¥n
    Nov 20 22:29:04 nicolas-Lemur kernel: [15667.535104] cpu[3] = 20¥n
    Nov 20 22:29:04 nicolas-Lemur kernel: [15668.047048] cpu[0] = 14¥n
    Nov 20 22:29:04 nicolas-Lemur kernel: [15668.047052] cpu[3] = 21¥n
    Nov 20 22:29:04 nicolas-Lemur kernel: [15668.047055] cpu[1] = 11¥n
    Nov 20 22:29:04 nicolas-Lemur kernel: [15668.558978] cpu[3] = 22¥n
    Nov 20 22:29:04 nicolas-Lemur kernel: [15668.558983] cpu[2] = 15¥n
    Nov 20 22:29:05 nicolas-Lemur kernel: [15668.558992] cpu[3] = 23¥n
    Nov 20 22:29:05 nicolas-Lemur kernel: [15669.070890] cpu[0] = 15¥n
    Nov 20 22:29:05 nicolas-Lemur kernel: [15669.070932] cpu[2] = 16¥n
    Nov 20 22:29:05 nicolas-Lemur kernel: [15669.070950] cpu[1] = 12¥n
    Nov 20 22:29:05 nicolas-Lemur kernel: [15669.582882] cpu[0] = 16¥n
    Nov 20 22:29:05 nicolas-Lemur kernel: [15669.582885] cpu[2] = 17¥n
    Nov 20 22:29:06 nicolas-Lemur kernel: [15669.582923] cpu[1] = 13¥n
    Nov 20 22:29:06 nicolas-Lemur kernel: [15670.094829] cpu[3] = 24¥n
    Nov 20 22:29:06 nicolas-Lemur kernel: [15670.094832] cpu[1] = 14¥n
    Nov 20 22:29:06 nicolas-Lemur kernel: [15670.094840] cpu[1] = 15¥n
    Nov 20 22:29:06 nicolas-Lemur kernel: [15670.606790] cpu[3] = 25¥n
    Nov 20 22:29:06 nicolas-Lemur kernel: [15670.606793] cpu[1] = 16¥n
    Nov 20 22:29:07 nicolas-Lemur kernel: [15670.606801] cpu[1] = 17¥n
    Nov 20 22:29:07 nicolas-Lemur kernel: [15671.118851] cpu[2] = 18¥n
    Nov 20 22:29:07 nicolas-Lemur kernel: [15671.118864] cpu[3] = 26¥n
    Nov 20 22:29:07 nicolas-Lemur kernel: [15671.118866] cpu[1] = 18¥n
    Nov 20 22:29:07 nicolas-Lemur kernel: [15671.630732] cpu[2] = 19¥n
    Nov 20 22:29:07 nicolas-Lemur kernel: [15671.630737] cpu[3] = 27¥n
    Nov 20 22:29:08 nicolas-Lemur kernel: [15671.630739] cpu[1] = 19¥n
    Nov 20 22:29:08 nicolas-Lemur kernel: [15672.142686] cpu[2] = 20¥n
    Nov 20 22:29:08 nicolas-Lemur kernel: [15672.142690] cpu[1] = 20¥n
    Nov 20 22:29:08 nicolas-Lemur kernel: [15672.142692] cpu[3] = 28¥n
    Nov 20 22:29:08 nicolas-Lemur kernel: [15672.654619] cpu[3] = 29¥n
    Nov 20 22:29:08 nicolas-Lemur kernel: [15672.654621] cpu[1] = 21¥n
    Nov 20 22:29:09 nicolas-Lemur kernel: [15672.654630] cpu[0] = 17¥n
    Nov 20 22:29:09 nicolas-Lemur kernel: [15673.166583] cpu[0] = 18¥n
    Nov 20 22:29:09 nicolas-Lemur kernel: [15673.166588] cpu[3] = 30¥n
    Nov 20 22:29:09 nicolas-Lemur kernel: [15673.166590] cpu[1] = 22¥n
    Nov 20 22:29:09 nicolas-Lemur kernel: [15673.678532] cpu[0] = 19¥n
    Nov 20 22:29:09 nicolas-Lemur kernel: [15673.678542] cpu[1] = 23¥n
    Nov 20 22:29:10 nicolas-Lemur kernel: [15673.678545] cpu[3] = 31¥n
    Nov 20 22:29:10 nicolas-Lemur kernel: [15674.190516] cpu[1] = 24¥n
    Nov 20 22:29:10 nicolas-Lemur kernel: [15674.190518] cpu[3] = 32¥n
    Nov 20 22:29:10 nicolas-Lemur kernel: [15674.194502] cpu[0] = 20¥n
    Nov 20 22:29:10 nicolas-Lemur kernel: [15674.702399] cpu[0] = 21¥n
    Nov 20 22:29:10 nicolas-Lemur kernel: [15674.702412] cpu[3] = 33¥n
    Nov 20 22:29:11 nicolas-Lemur kernel: [15674.702414] cpu[1] = 25¥n
    Nov 20 22:29:11 nicolas-Lemur kernel: [15675.214403] cpu[0] = 22¥n
    Nov 20 22:29:11 nicolas-Lemur kernel: [15675.214408] cpu[3] = 34¥n
    Nov 20 22:29:11 nicolas-Lemur kernel: [15675.218756] cpu[1] = 26¥n
    Nov 20 22:29:11 nicolas-Lemur kernel: [15675.726368] cpu[3] = 35¥n
    Nov 20 22:29:11 nicolas-Lemur kernel: [15675.726370] cpu[1] = 27¥n
    Nov 20 22:29:12 nicolas-Lemur kernel: [15675.726374] cpu[0] = 23¥n
    Nov 20 22:29:12 nicolas-Lemur kernel: [15676.238285] cpu[3] = 36¥n
    Nov 20 22:29:12 nicolas-Lemur kernel: [15676.238288] cpu[1] = 28¥n
    Nov 20 22:29:12 nicolas-Lemur kernel: [15676.238300] cpu[0] = 24¥n
    Nov 20 22:29:12 nicolas-Lemur kernel: [15676.750281] cpu[1] = 29¥n
    Nov 20 22:29:12 nicolas-Lemur kernel: [15676.750283] cpu[3] = 37¥n
    Nov 20 22:29:13 nicolas-Lemur kernel: [15676.750303] cpu[0] = 25¥n
    Nov 20 22:29:13 nicolas-Lemur kernel: [15677.262188] cpu[0] = 26¥n
    Nov 20 22:29:13 nicolas-Lemur kernel: [15677.262200] cpu[1] = 30¥n
    Nov 20 22:29:13 nicolas-Lemur kernel: [15677.262211] cpu[1] = 31¥n
    Nov 20 22:29:13 nicolas-Lemur kernel: [15677.774164] cpu[2] = 21¥n
    Nov 20 22:29:13 nicolas-Lemur kernel: [15677.774168] cpu[3] = 38¥n
    Nov 20 22:29:14 nicolas-Lemur kernel: [15677.774210] cpu[0] = 27¥n
    Nov 20 22:29:14 nicolas-Lemur kernel: [15678.286145] cpu[2] = 22¥n
    Nov 20 22:29:14 nicolas-Lemur kernel: [15678.286155] cpu[3] = 39¥n
    Nov 20 22:29:14 nicolas-Lemur kernel: [15678.286163] cpu[0] = 28¥n
    Nov 20 22:29:14 nicolas-Lemur kernel: [15678.798074] cpu[3] = 40¥n
    Nov 20 22:29:14 nicolas-Lemur kernel: [15678.798080] cpu[0] = 29¥n
    Nov 20 22:29:15 nicolas-Lemur kernel: [15678.798082] cpu[2] = 23¥n
    Nov 20 22:29:15 nicolas-Lemur kernel: [15679.310065] cpu[3] = 41¥n
    Nov 20 22:29:15 nicolas-Lemur kernel: [15679.314036] cpu[0] = 30¥n
    Nov 20 22:29:16 nicolas-Lemur kernel: [15679.314038] cpu[2] = 24¥n
    Nov 20 22:29:16 nicolas-Lemur kernel: [15679.821972] cpu[2] = 25¥n
    Nov 20 22:29:16 nicolas-Lemur kernel: [15679.821974] cpu[0] = 31¥n
    Nov 20 22:29:16 nicolas-Lemur kernel: [15679.821978] cpu[3] = 42¥n
    Nov 20 22:29:16 nicolas-Lemur kernel: [15680.333935] cpu[3] = 43¥n
    Nov 20 22:29:16 nicolas-Lemur kernel: [15680.333939] cpu[0] = 32¥n
    Nov 20 22:29:17 nicolas-Lemur kernel: [15680.333941] cpu[2] = 26¥n
    Nov 20 22:29:17 nicolas-Lemur kernel: [15680.845908] cpu[0] = 33¥n
    Nov 20 22:29:17 nicolas-Lemur kernel: [15680.845909] cpu[2] = 27¥n
    Nov 20 22:29:17 nicolas-Lemur kernel: [15680.845911] cpu[3] = 44¥n
    Nov 20 22:29:17 nicolas-Lemur kernel: [15681.357827] cpu[0] = 34¥n
    Nov 20 22:29:17 nicolas-Lemur kernel: [15681.357830] cpu[2] = 28¥n
    Nov 20 22:29:18 nicolas-Lemur kernel: [15681.357833] cpu[3] = 45¥n
    Nov 20 22:29:18 nicolas-Lemur kernel: [15681.869799] cpu[0] = 35¥n
    Nov 20 22:29:18 nicolas-Lemur kernel: [15681.869801] cpu[2] = 29¥n
    Nov 20 22:29:18 nicolas-Lemur kernel: [15681.869805] cpu[3] = 46¥n
    Nov 20 22:29:18 nicolas-Lemur kernel: [15682.381816] cpu[0] = 36¥n
    Nov 20 22:29:18 nicolas-Lemur kernel: [15682.381818] cpu[2] = 30¥n
    Nov 20 22:29:19 nicolas-Lemur kernel: [15682.381824] cpu[3] = 47¥n
    Nov 20 22:29:19 nicolas-Lemur kernel: [15682.893769] cpu[2] = 31¥n
    Nov 20 22:29:19 nicolas-Lemur kernel: [15682.893772] cpu[0] = 37¥n
    Nov 20 22:29:19 nicolas-Lemur kernel: [15682.893775] cpu[3] = 48¥n
    Nov 20 22:29:19 nicolas-Lemur kernel: [15683.405697] cpu[2] = 32¥n
    Nov 20 22:29:19 nicolas-Lemur kernel: [15683.405699] cpu[0] = 38¥n
    Nov 20 22:29:20 nicolas-Lemur kernel: [15683.405701] cpu[3] = 49¥n
    Nov 20 22:29:20 nicolas-Lemur kernel: [15683.917587] cpu[1] = 32¥n
    Nov 20 22:29:20 nicolas-Lemur kernel: [15683.917620] cpu[0] = 39¥n
    Nov 20 22:29:20 nicolas-Lemur kernel: [15683.917622] cpu[2] = 33¥n
    Nov 20 22:29:20 nicolas-Lemur kernel: [15684.429527] cpu[0] = 40¥n
    Nov 20 22:29:20 nicolas-Lemur kernel: [15684.429528] cpu[1] = 33¥n
    Nov 20 22:29:21 nicolas-Lemur kernel: [15684.429529] cpu[2] = 34¥n
    Nov 20 22:29:21 nicolas-Lemur kernel: [15684.941512] cpu[2] = 35¥n
    Nov 20 22:29:21 nicolas-Lemur kernel: [15684.941527] cpu[1] = 34¥n
    Nov 20 22:29:21 nicolas-Lemur kernel: [15684.941530] cpu[1] = 35¥n
    Nov 20 22:29:21 nicolas-Lemur kernel: [15685.453435] cpu[0] = 41¥n
    Nov 20 22:29:21 nicolas-Lemur kernel: [15685.453449] cpu[3] = 50¥n
    Nov 20 22:29:22 nicolas-Lemur kernel: [15685.453459] cpu[1] = 36¥n
    Nov 20 22:29:22 nicolas-Lemur kernel: [15685.965424] cpu[3] = 51¥n
    Nov 20 22:29:22 nicolas-Lemur kernel: [15685.965425] cpu[1] = 37¥n
    Nov 20 22:29:22 nicolas-Lemur kernel: [15685.965426] cpu[0] = 42¥n
    Nov 20 22:29:22 nicolas-Lemur kernel: [15686.477385] cpu[0] = 43¥n
    Nov 20 22:29:22 nicolas-Lemur kernel: [15686.477387] cpu[1] = 38¥n
    Nov 20 22:29:23 nicolas-Lemur kernel: [15686.477392] cpu[0] = 44¥n
    Nov 20 22:29:23 nicolas-Lemur kernel: [15686.989409] cpu[0] = 45¥n
    Nov 20 22:29:23 nicolas-Lemur kernel: [15686.989415] cpu[1] = 39¥n
    Nov 20 22:29:23 nicolas-Lemur kernel: [15686.989427] cpu[0] = 46¥n
    Nov 20 22:29:23 nicolas-Lemur kernel: [15687.501303] cpu[2] = 36¥n
    Nov 20 22:29:23 nicolas-Lemur kernel: [15687.501352] cpu[0] = 47¥n
    Nov 20 22:29:24 nicolas-Lemur kernel: [15687.501368] cpu[1] = 40¥n
    Nov 20 22:29:24 nicolas-Lemur kernel: [15688.013260] cpu[3] = 52¥n
    Nov 20 22:29:24 nicolas-Lemur kernel: [15688.013283] cpu[2] = 37¥n
    Nov 20 22:29:24 nicolas-Lemur kernel: [15688.013285] cpu[0] = 48¥n
    Nov 20 22:29:24 nicolas-Lemur kernel: [15688.525274] cpu[3] = 53¥n
    Nov 20 22:29:24 nicolas-Lemur kernel: [15688.525282] cpu[2] = 38¥n
    Nov 20 22:29:25 nicolas-Lemur kernel: [15688.525284] cpu[0] = 49¥n
    Nov 20 22:29:25 nicolas-Lemur kernel: [15689.037214] cpu[3] = 54¥n
    Nov 20 22:29:25 nicolas-Lemur kernel: [15689.037221] cpu[2] = 39¥n
    Nov 20 22:29:25 nicolas-Lemur kernel: [15689.041245] cpu[2] = 40¥n
    Nov 20 22:29:25 nicolas-Lemur kernel: [15689.549130] cpu[0] = 50¥n
    Nov 20 22:29:25 nicolas-Lemur kernel: [15689.549179] cpu[2] = 41¥n
    Nov 20 22:29:26 nicolas-Lemur kernel: [15689.549185] cpu[2] = 42¥n
    Nov 20 22:29:26 nicolas-Lemur kernel: [15690.061118] cpu[2] = 43¥n
    Nov 20 22:29:26 nicolas-Lemur kernel: [15690.061119] cpu[0] = 51¥n
    Nov 20 22:29:26 nicolas-Lemur kernel: [15690.061123] cpu[3] = 55¥n
    Nov 20 22:29:26 nicolas-Lemur kernel: [15690.573177] cpu[2] = 44¥n
    Nov 20 22:29:26 nicolas-Lemur kernel: [15690.573179] cpu[0] = 52¥n
    Nov 20 22:29:27 nicolas-Lemur kernel: [15690.577084] cpu[3] = 56¥n
    Nov 20 22:29:27 nicolas-Lemur kernel: [15691.085012] cpu[3] = 57¥n
    Nov 20 22:29:27 nicolas-Lemur kernel: [15691.085031] cpu[2] = 45¥n
    Nov 20 22:29:27 nicolas-Lemur kernel: [15691.085036] cpu[1] = 41¥n
    Nov 20 22:29:27 nicolas-Lemur kernel: [15691.596995] cpu[3] = 58¥n
    Nov 20 22:29:27 nicolas-Lemur kernel: [15691.600983] cpu[0] = 53¥n
    Nov 20 22:29:28 nicolas-Lemur kernel: [15691.600990] cpu[2] = 46¥n
    Nov 20 22:29:28 nicolas-Lemur kernel: [15692.108937] cpu[1] = 42¥n
    Nov 20 22:29:28 nicolas-Lemur kernel: [15692.108967] cpu[3] = 59¥n
    Nov 20 22:29:28 nicolas-Lemur kernel: [15692.108971] cpu[3] = 60¥n
    Nov 20 22:29:28 nicolas-Lemur kernel: [15692.620879] cpu[2] = 47¥n
    Nov 20 22:29:28 nicolas-Lemur kernel: [15692.620924] cpu[0] = 54¥n
    Nov 20 22:29:29 nicolas-Lemur kernel: [15692.620971] cpu[3] = 61¥n
    Nov 20 22:29:29 nicolas-Lemur kernel: [15693.132889] cpu[3] = 62¥n
    Nov 20 22:29:29 nicolas-Lemur kernel: [15693.136857] cpu[1] = 43¥n
    Nov 20 22:29:29 nicolas-Lemur kernel: [15693.136871] cpu[2] = 48¥n
    Nov 20 22:29:29 nicolas-Lemur kernel: [15693.644833] cpu[1] = 44¥n
    Nov 20 22:29:29 nicolas-Lemur kernel: [15693.644834] cpu[3] = 63¥n
    Nov 20 22:29:30 nicolas-Lemur kernel: [15693.644850] cpu[2] = 49¥n
    Nov 20 22:29:30 nicolas-Lemur kernel: [15694.156729] cpu[1] = 45¥n
    Nov 20 22:29:30 nicolas-Lemur kernel: [15694.156743] cpu[2] = 50¥n
    Nov 20 22:29:30 nicolas-Lemur kernel: [15694.156744] cpu[3] = 64¥n
    Nov 20 22:29:30 nicolas-Lemur kernel: [15694.668794] cpu[3] = 65¥n
    Nov 20 22:29:30 nicolas-Lemur kernel: [15694.668797] cpu[1] = 46¥n
    Nov 20 22:29:31 nicolas-Lemur kernel: [15694.672756] cpu[2] = 51¥n
    Nov 20 22:29:31 nicolas-Lemur kernel: [15695.180708] cpu[1] = 47¥n
    Nov 20 22:29:31 nicolas-Lemur kernel: [15695.180710] cpu[3] = 66¥n
    Nov 20 22:29:31 nicolas-Lemur kernel: [15695.184702] cpu[3] = 67¥n
    Nov 20 22:29:31 nicolas-Lemur kernel: [15695.692704] cpu[0] = 55¥n
    Nov 20 22:29:31 nicolas-Lemur kernel: [15695.692729] cpu[1] = 48¥n
    Nov 20 22:29:32 nicolas-Lemur kernel: [15695.692731] cpu[3] = 68¥n
    Nov 20 22:29:32 nicolas-Lemur kernel: [15696.204653] cpu[1] = 49¥n
    Nov 20 22:29:32 nicolas-Lemur kernel: [15696.204655] cpu[3] = 69¥n
    Nov 20 22:29:32 nicolas-Lemur kernel: [15696.204660] cpu[0] = 56¥n
    Nov 20 22:29:32 nicolas-Lemur kernel: [15696.716620] cpu[0] = 57¥n
    Nov 20 22:29:32 nicolas-Lemur kernel: [15696.716630] cpu[1] = 50¥n
    Nov 20 22:29:33 nicolas-Lemur kernel: [15696.716636] cpu[1] = 51¥n
    Nov 20 22:29:33 nicolas-Lemur kernel: [15697.228548] cpu[2] = 52¥n
    Nov 20 22:29:33 nicolas-Lemur kernel: [15697.228553] cpu[1] = 52¥n
    Nov 20 22:29:33 nicolas-Lemur kernel: [15697.228563] cpu[1] = 53¥n
    Nov 20 22:29:33 nicolas-Lemur kernel: [15697.740520] cpu[3] = 70¥n
    Nov 20 22:29:33 nicolas-Lemur kernel: [15697.740555] cpu[2] = 53¥n
    Nov 20 22:29:34 nicolas-Lemur kernel: [15697.740557] cpu[1] = 54¥n
    Nov 20 22:29:34 nicolas-Lemur kernel: [15698.252463] cpu[3] = 71¥n
    Nov 20 22:29:34 nicolas-Lemur kernel: [15698.252501] cpu[2] = 54¥n
    Nov 20 22:29:34 nicolas-Lemur kernel: [15698.252510] cpu[0] = 58¥n
    Nov 20 22:29:34 nicolas-Lemur kernel: [15698.764417] cpu[3] = 72¥n
    Nov 20 22:29:34 nicolas-Lemur kernel: [15698.764420] cpu[0] = 59¥n
    Nov 20 22:29:35 nicolas-Lemur kernel: [15698.764423] cpu[2] = 55¥n
    Nov 20 22:29:35 nicolas-Lemur kernel: [15699.276382] cpu[2] = 56¥n
    Nov 20 22:29:35 nicolas-Lemur kernel: [15699.276384] cpu[0] = 60¥n
    Nov 20 22:29:35 nicolas-Lemur kernel: [15699.276391] cpu[0] = 61¥n
    Nov 20 22:29:35 nicolas-Lemur kernel: [15699.788392] cpu[2] = 57¥n
    Nov 20 22:29:35 nicolas-Lemur kernel: [15699.788394] cpu[0] = 62¥n
    Nov 20 22:29:36 nicolas-Lemur kernel: [15699.788402] cpu[0] = 63¥n
    Nov 20 22:29:36 nicolas-Lemur kernel: [15700.300355] cpu[0] = 64¥n
    Nov 20 22:29:36 nicolas-Lemur kernel: [15700.300365] cpu[0] = 65¥n
    Nov 20 22:29:37 nicolas-Lemur kernel: [15700.300371] cpu[0] = 66¥n
    Nov 20 22:29:37 nicolas-Lemur kernel: [15700.812240] cpu[2] = 58¥n
    Nov 20 22:29:37 nicolas-Lemur kernel: [15700.812296] cpu[0] = 67¥n
    Nov 20 22:29:37 nicolas-Lemur kernel: [15700.812303] cpu[0] = 68¥n
    Nov 20 22:29:37 nicolas-Lemur kernel: [15701.324222] cpu[2] = 59¥n
    Nov 20 22:29:37 nicolas-Lemur kernel: [15701.324224] cpu[0] = 69¥n
    Nov 20 22:29:38 nicolas-Lemur kernel: [15701.324231] cpu[2] = 60¥n
    Nov 20 22:29:38 nicolas-Lemur kernel: [15701.836169] cpu[0] = 70¥n
    Nov 20 22:29:38 nicolas-Lemur kernel: [15701.836169] cpu[2] = 61¥n
    Nov 20 22:29:38 nicolas-Lemur kernel: [15701.836171] cpu[2] = 62¥n
    Nov 20 22:29:38 nicolas-Lemur kernel: [15702.348164] cpu[2] = 63¥n
    Nov 20 22:29:38 nicolas-Lemur kernel: [15702.348165] cpu[0] = 71¥n
    Nov 20 22:29:39 nicolas-Lemur kernel: [15702.348170] cpu[2] = 64¥n
    Nov 20 22:29:39 nicolas-Lemur kernel: [15702.860115] cpu[2] = 65¥n
    Nov 20 22:29:39 nicolas-Lemur kernel: [15702.860122] cpu[2] = 66¥n
    Nov 20 22:29:39 nicolas-Lemur kernel: [15702.860127] cpu[2] = 67¥n
    Nov 20 22:29:39 nicolas-Lemur kernel: [15703.372072] cpu[0] = 72¥n
    Nov 20 22:29:39 nicolas-Lemur kernel: [15703.372098] cpu[3] = 73¥n
    Nov 20 22:29:40 nicolas-Lemur kernel: [15703.372120] cpu[2] = 68¥n
    Nov 20 22:29:40 nicolas-Lemur kernel: [15703.884045] cpu[3] = 74¥n
    Nov 20 22:29:40 nicolas-Lemur kernel: [15703.888086] cpu[2] = 69¥n
    Nov 20 22:29:40 nicolas-Lemur kernel: [15703.888088] cpu[0] = 73¥n
    Nov 20 22:29:40 nicolas-Lemur kernel: [15704.395961] cpu[0] = 74¥n
    Nov 20 22:29:40 nicolas-Lemur kernel: [15704.395962] cpu[2] = 70¥n
    Nov 20 22:29:41 nicolas-Lemur kernel: [15704.399965] cpu[2] = 71¥n
    Nov 20 22:29:41 nicolas-Lemur kernel: [15704.907976] cpu[0] = 75¥n
    Nov 20 22:29:41 nicolas-Lemur kernel: [15704.907977] cpu[3] = 75¥n
    Nov 20 22:29:41 nicolas-Lemur kernel: [15704.907988] cpu[2] = 72¥n
    Nov 20 22:29:41 nicolas-Lemur kernel: [15705.419975] cpu[3] = 76¥n
    Nov 20 22:29:41 nicolas-Lemur kernel: [15705.419979] cpu[2] = 73¥n
    Nov 20 22:29:42 nicolas-Lemur kernel: [15705.419981] cpu[0] = 76¥n
    Nov 20 22:29:42 nicolas-Lemur kernel: [15705.931939] cpu[2] = 74¥n
    Nov 20 22:29:42 nicolas-Lemur kernel: [15705.931942] cpu[0] = 77¥n
    Nov 20 22:29:42 nicolas-Lemur kernel: [15705.931946] cpu[3] = 77¥n
    Nov 20 22:29:42 nicolas-Lemur kernel: [15706.443837] cpu[3] = 78¥n
    Nov 20 22:29:42 nicolas-Lemur kernel: [15706.447833] cpu[2] = 75¥n
    Nov 20 22:29:43 nicolas-Lemur kernel: [15706.447833] cpu[0] = 78¥n
    Nov 20 22:29:43 nicolas-Lemur kernel: [15706.955782] cpu[3] = 79¥n
    Nov 20 22:29:43 nicolas-Lemur kernel: [15706.955788] cpu[0] = 79¥n
    Nov 20 22:29:43 nicolas-Lemur kernel: [15706.955794] cpu[0] = 80¥n
    Nov 20 22:29:43 nicolas-Lemur kernel: [15707.467715] cpu[2] = 76¥n
    Nov 20 22:29:43 nicolas-Lemur kernel: [15707.467718] cpu[1] = 55¥n
    Nov 20 22:29:44 nicolas-Lemur kernel: [15707.467739] cpu[0] = 81¥n
    Nov 20 22:29:44 nicolas-Lemur kernel: [15707.979744] cpu[3] = 80¥n
    Nov 20 22:29:44 nicolas-Lemur kernel: [15707.979831] cpu[1] = 56¥n
    Nov 20 22:29:44 nicolas-Lemur kernel: [15707.979840] cpu[1] = 57¥n
    Nov 20 22:29:44 nicolas-Lemur kernel: [15708.491715] cpu[2] = 77¥n
    Nov 20 22:29:44 nicolas-Lemur kernel: [15708.491717] cpu[0] = 82¥n
    Nov 20 22:29:45 nicolas-Lemur kernel: [15708.491828] cpu[1] = 58¥n
    Nov 20 22:29:45 nicolas-Lemur kernel: [15709.003712] cpu[1] = 59¥n
    Nov 20 22:29:45 nicolas-Lemur kernel: [15709.003738] cpu[2] = 78¥n
    Nov 20 22:29:45 nicolas-Lemur kernel: [15709.003742] cpu[0] = 83¥n
    Nov 20 22:29:45 nicolas-Lemur kernel: [15709.515588] cpu[3] = 81¥n
    Nov 20 22:29:45 nicolas-Lemur kernel: [15709.515602] cpu[0] = 84¥n
    Nov 20 22:29:46 nicolas-Lemur kernel: [15709.515643] cpu[3] = 82¥n
    Nov 20 22:29:46 nicolas-Lemur kernel: [15710.027576] cpu[3] = 83¥n
    Nov 20 22:29:46 nicolas-Lemur kernel: [15710.027584] cpu[3] = 84¥n
    Nov 20 22:29:46 nicolas-Lemur kernel: [15710.027600] cpu[2] = 79¥n
    Nov 20 22:29:46 nicolas-Lemur kernel: [15710.539487] cpu[1] = 60¥n
    Nov 20 22:29:46 nicolas-Lemur kernel: [15710.539507] cpu[0] = 85¥n
    Nov 20 22:29:47 nicolas-Lemur kernel: [15710.539533] cpu[2] = 80¥n
    Nov 20 22:29:47 nicolas-Lemur kernel: [15711.051486] cpu[0] = 86¥n
    Nov 20 22:29:47 nicolas-Lemur kernel: [15711.051498] cpu[1] = 61¥n
    Nov 20 22:29:47 nicolas-Lemur kernel: [15711.051501] cpu[2] = 81¥n
    Nov 20 22:29:47 nicolas-Lemur kernel: [15711.563473] cpu[0] = 87¥n
    Nov 20 22:29:47 nicolas-Lemur kernel: [15711.563475] cpu[2] = 82¥n
    Nov 20 22:29:48 nicolas-Lemur kernel: [15711.563484] cpu[1] = 62¥n
    Nov 20 22:29:48 nicolas-Lemur kernel: [15712.075408] cpu[3] = 85¥n
    Nov 20 22:29:48 nicolas-Lemur kernel: [15712.075459] cpu[1] = 63¥n
    Nov 20 22:29:48 nicolas-Lemur kernel: [15712.075467] cpu[1] = 64¥n
    Nov 20 22:29:48 nicolas-Lemur kernel: [15712.587370] cpu[1] = 65¥n
    Nov 20 22:29:48 nicolas-Lemur kernel: [15712.587372] cpu[0] = 88¥n
    Nov 20 22:29:49 nicolas-Lemur kernel: [15712.587373] cpu[1] = 66¥n
    Nov 20 22:29:49 nicolas-Lemur kernel: [15713.099366] cpu[3] = 86¥n
    Nov 20 22:29:49 nicolas-Lemur kernel: [15713.099429] cpu[1] = 67¥n
    Nov 20 22:29:49 nicolas-Lemur kernel: [15713.099436] cpu[1] = 68¥n
    Nov 20 22:29:49 nicolas-Lemur kernel: [15713.611421] cpu[3] = 87¥n
    Nov 20 22:29:49 nicolas-Lemur kernel: [15713.611423] cpu[1] = 69¥n
    Nov 20 22:29:50 nicolas-Lemur kernel: [15713.611433] cpu[1] = 70¥n
    Nov 20 22:29:50 nicolas-Lemur kernel: [15714.123316] cpu[3] = 88¥n
    Nov 20 22:29:50 nicolas-Lemur kernel: [15714.123322] cpu[1] = 71¥n
    Nov 20 22:29:50 nicolas-Lemur kernel: [15714.123330] cpu[1] = 72¥n
    Nov 20 22:29:50 nicolas-Lemur kernel: [15714.635268] cpu[3] = 89¥n
    Nov 20 22:29:50 nicolas-Lemur kernel: [15714.635269] cpu[1] = 73¥n
    Nov 20 22:29:51 nicolas-Lemur kernel: [15714.635285] cpu[2] = 83¥n
    Nov 20 22:29:51 nicolas-Lemur kernel: [15715.147220] cpu[3] = 90¥n
    Nov 20 22:29:51 nicolas-Lemur kernel: [15715.147223] cpu[2] = 84¥n
    Nov 20 22:29:51 nicolas-Lemur kernel: [15715.147224] cpu[1] = 74¥n
    Nov 20 22:29:51 nicolas-Lemur kernel: [15715.659179] cpu[3] = 91¥n
    Nov 20 22:29:51 nicolas-Lemur kernel: [15715.659217] cpu[0] = 89¥n
    Nov 20 22:29:52 nicolas-Lemur kernel: [15715.659236] cpu[2] = 85¥n
    Nov 20 22:29:52 nicolas-Lemur kernel: [15716.171198] cpu[0] = 90¥n
    Nov 20 22:29:52 nicolas-Lemur kernel: [15716.171200] cpu[2] = 86¥n
    Nov 20 22:29:52 nicolas-Lemur kernel: [15716.171211] cpu[3] = 92¥n
    Nov 20 22:29:52 nicolas-Lemur kernel: [15716.683159] cpu[0] = 91¥n
    Nov 20 22:29:52 nicolas-Lemur kernel: [15716.683161] cpu[2] = 87¥n
    Nov 20 22:29:53 nicolas-Lemur kernel: [15716.683179] cpu[3] = 93¥n
    Nov 20 22:29:53 nicolas-Lemur kernel: [15717.195025] cpu[3] = 94¥n
    Nov 20 22:29:53 nicolas-Lemur kernel: [15717.195027] cpu[0] = 92¥n
    Nov 20 22:29:53 nicolas-Lemur kernel: [15717.195033] cpu[3] = 95¥n
    Nov 20 22:29:53 nicolas-Lemur kernel: [15717.706990] cpu[1] = 75¥n
    Nov 20 22:29:53 nicolas-Lemur kernel: [15717.707001] cpu[2] = 88¥n
    Nov 20 22:29:54 nicolas-Lemur kernel: [15717.707023] cpu[0] = 93¥n
    Nov 20 22:29:54 nicolas-Lemur kernel: [15718.219017] cpu[0] = 94¥n
    Nov 20 22:29:54 nicolas-Lemur kernel: [15718.219019] cpu[2] = 89¥n
    Nov 20 22:29:54 nicolas-Lemur kernel: [15718.219045] cpu[1] = 76¥n
    Nov 20 22:29:54 nicolas-Lemur kernel: [15718.730981] cpu[0] = 95¥n
    Nov 20 22:29:54 nicolas-Lemur kernel: [15718.730982] cpu[2] = 90¥n
    Nov 20 22:29:55 nicolas-Lemur kernel: [15718.735014] cpu[1] = 77¥n
    Nov 20 22:29:55 nicolas-Lemur kernel: [15719.243017] cpu[0] = 96¥n
    Nov 20 22:29:55 nicolas-Lemur kernel: [15719.243022] cpu[3] = 96¥n
    Nov 20 22:29:55 nicolas-Lemur kernel: [15719.243037] cpu[0] = 97¥n
    Nov 20 22:29:55 nicolas-Lemur kernel: [15719.754848] cpu[0] = 98¥n
    Nov 20 22:29:55 nicolas-Lemur kernel: [15719.754849] cpu[3] = 97¥n
    Nov 20 22:29:56 nicolas-Lemur kernel: [15719.754851] cpu[0] = 99¥n
    Nov 20 22:29:56 nicolas-Lemur kernel: [15720.266870] cpu[2] = 91¥n
    Nov 20 22:29:56 nicolas-Lemur kernel: [15720.266905] cpu[3] = 98¥n
    Nov 20 22:29:56 nicolas-Lemur kernel: [15720.266907] cpu[0] = 100¥n
    Nov 20 22:29:56 nicolas-Lemur kernel: [15720.778845] cpu[3] = 99¥n
    Nov 20 22:29:56 nicolas-Lemur kernel: [15720.778856] cpu[1] = 78¥n
    Nov 20 22:29:57 nicolas-Lemur kernel: [15720.778858] cpu[2] = 92¥n
    Nov 20 22:29:57 nicolas-Lemur kernel: [15721.290820] cpu[3] = 100¥n
    Nov 20 22:29:57 nicolas-Lemur kernel: [15721.294799] cpu[2] = 93¥n
    Nov 20 22:29:58 nicolas-Lemur kernel: [15721.294804] cpu[1] = 79¥n
    Nov 20 22:29:58 nicolas-Lemur kernel: [15721.802784] cpu[1] = 80¥n
    Nov 20 22:29:58 nicolas-Lemur kernel: [15721.802789] cpu[2] = 94¥n
    Nov 20 22:29:58 nicolas-Lemur kernel: [15721.802792] cpu[3] = 101¥n
    Nov 20 22:30:22 nicolas-Lemur kernel: [15722.310937] [PERCPU]: Exiting module.¥n


Slide page 59
------------

This module did not run correctly. Impossible to remove it with rmmod or modprobe -rf


module code

    #include <linux/module.h>
    #include <linux/kernel.h>
    #include <linux/init.h>
    #include <linux/percpu.h>
    #include <linux/kthread.h>
    #include <linux/sched.h>
    #include <linux/delay.h>
    #include <linux/smp.h>

    #define PRINT_PREF "[PERCPU]: "

    struct task_struct *thread1, *thread2, *thread3;
    void *my_var2;
    static int thread_function(void *data)
    {
	    while(!kthread_should_stop()) {
		    int *local_ptr, cpu;
		    local_ptr = get_cpu_ptr(my_var2);
		    cpu = smp_processor_id();
		    (*local_ptr)++;
		    printk("cpu[%d] = %d¥n", cpu, *local_ptr);
		    put_cpu_var(my_var2);
		    msleep(500);
	    }
	    do_exit(0);
    }

    static int __init my_mod_init(void)
    {
	    int *local_ptr;
	    int cpu;

	    printk(PRINT_PREF " Entering module.¥n");

	    my_var2 = alloc_percpu(int);
	    if(!my_var2)
		    return -1;

	    for (cpu = 0; cpu <NR_CPUS; cpu++) {
		    local_ptr = per_cpu_ptr(my_var2, cpu);
		    *local_ptr = 0;
		    put_cpu();
	    }

	    wmb();

	    thread1 = kthread_run(thread_function, NULL, "percpu-thread1");
	    thread2 = kthread_run(thread_function, NULL, "percpu-thread2");
	    thread3 = kthread_run(thread_function, NULL, "percpu-thread3");

	    return 0;
    }

    static void __exit my_mod_exit(void)
    {
	    kthread_stop(thread1);
	    kthread_stop(thread2);
	    kthread_stop(thread3);

	    free_percpu(my_var2);

	    printk(PRINT_PREF "Exiting module.¥n");
    }

    module_init(my_mod_init);
    module_exit(my_mod_exit);

    MODULE_LICENSE("GPL");


out of printk()

    Nov 20 22:53:13 nicolas-Lemur kernel: [   59.569503] percpu2: loading out-of-tree module taints kernel.
    Nov 20 22:53:13 nicolas-Lemur kernel: [   59.569532] percpu2: module verification failed: signature and/or required key missing - tainting kernel
    Nov 20 22:53:13 nicolas-Lemur kernel: [   59.570577] [PERCPU]:  Entering module.¥n
    Nov 20 22:53:13 nicolas-Lemur kernel: [   59.570592] BUG: unable to handle kernel paging request at 00003767db5a8380
    Nov 20 22:53:13 nicolas-Lemur kernel: [   59.570637] IP: my_mod_init+0x43/0x1000 [percpu2]
    Nov 20 22:53:13 nicolas-Lemur kernel: [   59.570655] PGD 0 
    Nov 20 22:53:13 nicolas-Lemur kernel: [   59.570656] 
    Nov 20 22:53:13 nicolas-Lemur kernel: [   59.570667] Oops: 0002 [#1] SMP
    Nov 20 22:53:13 nicolas-Lemur kernel: [   59.570675] Modules linked in: percpu2(OE+) hid_generic hidp rfcomm ec_sys cmac bnep snd_hda_codec_hdmi snd_hda_codec_realtek snd_hda_codec_generic binfmt_misc nls_iso8859_1 snd_soc_skl snd_soc_skl_ipc snd_soc_sst_ipc snd_soc_sst_dsp snd_hda_ext_core snd_soc_sst_match snd_soc_core arc4 snd_compress ac97_bus intel_rapl snd_pcm_dmaengine x86_pkg_temp_thermal snd_hda_intel intel_powerclamp snd_hda_codec snd_hda_core snd_hwdep coretemp kvm_intel kvm snd_pcm irqbypass crct10dif_pclmul crc32_pclmul ghash_clmulni_intel snd_seq_midi snd_seq_midi_event snd_rawmidi pcbc snd_seq snd_seq_device snd_timer iwlmvm aesni_intel mac80211 aes_x86_64 crypto_simd glue_helper snd cryptd uvcvideo iwlwifi videobuf2_vmalloc videobuf2_memops input_leds joydev videobuf2_v4l2 videobuf2_core videodev serio_raw rtsx_pci_ms media
    Nov 20 22:53:13 nicolas-Lemur kernel: [   59.570837]  memstick cfg80211 soundcore mei_me btusb mei btrtl intel_pch_thermal shpchp hci_uart btbcm btqca btintel bluetooth mac_hid intel_lpss_acpi intel_lpss tpm_crb acpi_pad parport_pc ppdev lp parport ip_tables x_tables autofs4 btrfs xor raid6_pq dm_mirror dm_region_hash dm_log rtsx_pci_sdmmc i915 i2c_algo_bit drm_kms_helper psmouse syscopyarea sysfillrect sysimgblt fb_sys_fops drm r8169 ahci rtsx_pci mii libahci wmi video pinctrl_sunrisepoint pinctrl_intel i2c_hid hid fjes
    Nov 20 22:53:13 nicolas-Lemur kernel: [   59.570974] CPU: 3 PID: 3384 Comm: insmod Tainted: G           OE   4.10.0-38-generic #42-Ubuntu
    Nov 20 22:53:13 nicolas-Lemur kernel: [   59.571002] Hardware name: System76                        Lemur/Lemur, BIOS 5.12 02/17/2017
    Nov 20 22:53:13 nicolas-Lemur kernel: [   59.571025] task: ffff88b3bbc41700 task.stack: ffffa01c83d6c000
    Nov 20 22:53:13 nicolas-Lemur kernel: [   59.571053] RIP: 0010:my_mod_init+0x43/0x1000 [percpu2]
    Nov 20 22:53:13 nicolas-Lemur kernel: [   59.571074] RSP: 0018:ffffa01c83d6fc98 EFLAGS: 00010283
    Nov 20 22:53:13 nicolas-Lemur kernel: [   59.571092] RAX: 0000000000000020 RBX: ffffffffc02fc000 RCX: ffffffff8a5a2000
    Nov 20 22:53:13 nicolas-Lemur kernel: [   59.571115] RDX: 0000376851006380 RSI: 0000000000000000 RDI: ffffffff8a593780
    Nov 20 22:53:13 nicolas-Lemur kernel: [   59.571139] RBP: ffffa01c83d6fca0 R08: fffffffffffffff8 R09: ffffc01c7fd86380
    Nov 20 22:53:13 nicolas-Lemur kernel: [   59.571160] R10: 00000000000011ec R11: 0000000000006361 R12: ffffa01c83d6fea8
    Nov 20 22:53:13 nicolas-Lemur kernel: [   59.571181] R13: 0000000000000000 R14: ffff88b3f20e8d20 R15: ffff88b3f20e8d68
    Nov 20 22:53:13 nicolas-Lemur kernel: [   59.571208] FS:  00007f56f16fc700(0000) GS:ffff88b42ed80000(0000) knlGS:0000000000000000
    Nov 20 22:53:13 nicolas-Lemur kernel: [   59.571239] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033



