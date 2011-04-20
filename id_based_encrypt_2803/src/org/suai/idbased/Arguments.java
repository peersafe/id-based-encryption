/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package org.suai.idbased;

/**
 *
 * @author foxneig
 */
public class Arguments {
    public String [] args = null;
    public String mpk_path = null;
    public String msk_path1 = null;
    public String msk_path2 = null;
    public String id = null;
    public String sk_path = null;
    public String in_path = null;
    public String out_path = null;
    public String sks_path = null;
    public int    security = 0;
    public int command_type = 0;
    public Arguments (String [] args) {
        this.args = args;
    }
    public void getCommand () {
        if (args.length == 0) {
            this.command_type = -1;
            return;
        }
        if (args[0].equals("setup")) this.command_type = 0;
        else
            if(args[0].equals("keyextract")) this.command_type = 1;
        else
            if (args[0].equals("encrypt")) this.command_type = 2;
            else
                if (args[0].equals("decrypt")) this.command_type = 3;
                else
                    if (args[0].equals("sign")) this.command_type = 4;
                    else
                        if (args[0].equals("verify")) this.command_type = 5;
                        else
                            if (args[0].equals("--help")) this.command_type = 6;
                            else
                            this.command_type=-1;

    }
    private void verifyCorrect (int idx) {
        if (idx > args.length) {
        Util.invalidParameters();
        System.exit(0);
        }

    }
      public void extractArgs () {

        for (int i = 1; i < args.length; i++) {
            if (args[i].equals("-mpk")) {
                verifyCorrect(i+1);
                this.mpk_path = args[i+1];
               
            }
            else
                if (args[i].equals("-msk")) {
                    verifyCorrect(i+1);
                    verifyCorrect(i+2);

                    this.msk_path1 = args[i+1];
                    this.msk_path2 = args[i+2];
                }
 else
     if (args[i].equals("-id")) {
         verifyCorrect(i+1);
         this.id = args[i+1];

     }
 else
     if (args[i].equals("-in")) {
         verifyCorrect(i+1);
         this.in_path = args[i+1];
     }
 else
     if (args[i].equals("-out")) {
         verifyCorrect(i+1);
         this.out_path = args[i+1];
     }
 else
     if (args[i].equals("-sk")) {
         verifyCorrect(i+1);
         this.sk_path = args[i+1];
     }
 else
     if (args[i].equals("-security")) {
         verifyCorrect(i+1);
         this.security = Integer.parseInt(args[i+1]);
     }
 else
      if (args[i].equals("-sks")) {
         verifyCorrect(i+1);
         this.sks_path = args[i+1];
     }
          }

    }
      public void verifyRequiredParameters () {
          if (this.command_type == 0 && this.security == 0) {
              Util.invalidParameters();
              System.exit(0);
          }
          if (this.command_type == 1 && this.id == null) {
              Util.invalidParameters();
              System.exit(0);
          }
           if (this.command_type == 2 && (this.id == null || this.in_path == null || this.out_path == null)) {
              Util.invalidParameters();
              System.exit(0);
          }
           if (this.command_type == 3 && ((this.id == null && this.sk_path == null) || this.in_path == null || this.out_path == null)) {
              Util.invalidParameters();
              System.exit(0);
          }
           if (this.command_type == 4 && ((this.sk_path == null && this.id == null) || this.in_path == null || this.out_path == null)) {
              Util.invalidParameters();
              System.exit(0);
          }
           if (this.command_type == 5 && (this.in_path == null)) {
              Util.invalidParameters();
              System.exit(0);
          }



      }
}
