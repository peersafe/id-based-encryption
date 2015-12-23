package org.suai.idbased;

import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import org.suai.idbased.Main.Arguments.commands;
import org.suai.idbased.util.*;
import org.suai.idbased.pkg.*;
import org.suai.idbased.crypto.*;
import org.suai.idbased.keymng.*;

public class Main {

	private static FileOutputStream mpkf;
	private static FileOutputStream mskf;
	private static FileOutputStream default_mpkf;
	private static FileOutputStream default_mskf;
	private static DataOutputStream dmpkf;
	private static DataOutputStream default_dmpkf;
	private static DataOutputStream dmskf;
	private static DataOutputStream default_dmskf;
	private static FileOutputStream mskf2;
	private static FileOutputStream mskf1;
	private static DataOutputStream dmskf1;
	private static DataOutputStream dmskf2;
	private static FileOutputStream default_mskf1;
	private static DataOutputStream default_dmskf1;
	private static FileOutputStream default_mskf2;
	private static DataOutputStream default_dmskf2;
	private static FileOutputStream skef;
	private static DataOutputStream dskef;
	private static FileOutputStream sksf;

	public static class Arguments {

		public String[] args = null;
		public String keystoragePath = null;
		public String mpk_path = null;
		public String msk_path1 = null;
		public String msk_path2 = null;
		public String id = null;
		public String sk_path = null;
		public String in_path = null;
		public String out_path = null;
		public String sks_path = null;
		public String keyStorage = null;
		public String password = null;
		public int security = 0;
		private String sender = null;
		private String recip = null;
		private String domain = null;

		public enum commands {
			setup, keyextract, encrypt, decrypt, help, notfound;
		}

		commands command_type;

		public Arguments(String[] args) {
			this.args = args;
		}

		public commands getCommand() {
			if (args.length == 0) {
				this.command_type = commands.notfound;
				return commands.notfound;
			}
			if (args[0].equals("setup")) {
				this.command_type = commands.setup;
			} else if (args[0].equals("keyextract")) {
				this.command_type = commands.keyextract;
			} else if (args[0].equals("encrypt")) {
				this.command_type = commands.encrypt;
			} else if (args[0].equals("decrypt")) {
				this.command_type = commands.decrypt;
			}

			else if (args[0].equals("help")) {
				this.command_type = commands.help;
			} else

			{
				this.command_type = commands.notfound;
			}
			return this.command_type;

		}

		private void verifyCorrect(int idx) {
			if (idx >= args.length) {
				Util.invalidParameters();
				System.exit(0);
			}

		}

		public void extractArgs() {

			for (int i = 1; i < args.length; i++) {
				if (args[i].equals("-mpk")) {
					verifyCorrect(i + 1);
					this.mpk_path = args[i + 1];

				} else if (args[i].equals("-keystorage")) {
					verifyCorrect(i + 1);
					this.keystoragePath = args[i + 1];
				} else if (args[i].equals("-id")) {
					verifyCorrect(i + 1);
					this.id = args[i + 1];

				} else if (args[i].equals("-from")) {
					verifyCorrect(i + 1);
					this.sender = args[i + 1];

				} else if (args[i].equals("-to")) {
					verifyCorrect(i + 1);
					this.recip = args[i + 1];

				} else if (args[i].equals("-in")) {
					verifyCorrect(i + 1);
					this.in_path = args[i + 1];
				} else if (args[i].equals("-out")) {
					verifyCorrect(i + 1);
					this.out_path = args[i + 1];
				} else if (args[i].equals("-sk")) {
					verifyCorrect(i + 1);
					this.sk_path = args[i + 1];
				} else if (args[i].equals("-security")) {
					verifyCorrect(i + 1);
					this.security = Integer.parseInt(args[i + 1]);
					if (this.security <= 0) {
						Util.invalidParameters();
						System.exit(0);
					}
				} else if (args[i].equals("-sks")) {
					verifyCorrect(i + 1);
					this.sks_path = args[i + 1];
				}

				else if (args[i].equals("-password")) {
					verifyCorrect(i + 1);
					this.password = args[i + 1];

				} else if (args[i].equals("-domain")) {
					verifyCorrect(i + 1);
					this.domain = args[i + 1];

				}
			}

		}

		public void verifyRequiredParameters() {
			if (this.command_type == commands.setup
					&& (this.security == 0 || this.keystoragePath == null
							|| this.password == null || this.mpk_path == null || this.domain == null)) {
				Util.invalidParameters();
				System.exit(0);
			}
			if (this.command_type == commands.keyextract
					&& (this.id == null || this.sk_path == null
							|| this.sks_path == null
							|| this.keystoragePath == null || this.password == null)) {
				Util.invalidParameters();
				System.exit(0);
			}
			if (this.command_type == commands.encrypt
					&& (this.recip == null || this.in_path == null
							|| this.out_path == null || this.sks_path == null || this.mpk_path == null)) {
				Util.invalidParameters();
				System.exit(0);
			}
			if (this.command_type == commands.decrypt
					&& (this.sender == null || this.sk_path == null
							|| this.in_path == null || this.out_path == null
							|| this.mpk_path == null || this.recip == null)) {
				Util.invalidParameters();
				System.exit(0);
			}

		}
	}

	public static void main(String[] args) throws UnsupportedEncodingException,
			FileNotFoundException, NoSuchAlgorithmException,
			NoSuchPaddingException, InvalidKeyException, IOException {

		// Client client = new Client();
		Arguments argum = new Arguments(args);
		argum.getCommand();
		if (argum.command_type == commands.notfound) {
			Util.usage();
			System.exit(1);
		}
		argum.extractArgs();

		switch (argum.command_type) {
		case setup: {

			argum.verifyRequiredParameters();
			int security = argum.security;
			System.out.print("Private Key Generator initialization starting: ");
			PKG pkg = new PKG(security);
			pkg.setup();
			System.out.println("Done.");
			System.out.println("Master Public Key length: " + argum.security
					* 2 + " bit");
			System.out.println("Master Secret Key length: " + argum.security
					+ " bit");
			System.out.println("Public signing exponent: "
					+ pkg.getSigningPublicKey());
			System.out.print("Adding keydata into " + argum.keystoragePath
					+ ": ");

			KeyStorage ks = new KeyStorage(argum.keystoragePath);
			try {
				ks.addKey(argum.domain, pkg.getMPK().toByteArray(), pkg
						.getMSK1().toByteArray(), pkg.getMSK2().toByteArray(),
						argum.password);
			} catch (IllegalBlockSizeException ex) {
				Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null,
						ex);
			} catch (BadPaddingException ex) {
				Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null,
						ex);
			}
			System.out.println("Done.");
			System.out.println("Domain Name: " + argum.domain);
			System.out.println("Master Public Key: " + pkg.getMPK());
			FileOutputStream mpkf1 = new FileOutputStream(argum.mpk_path);
			mpkf1.write(pkg.getMPK().toByteArray());
			mpkf1.close();
			System.out.println("MPK saved into " + argum.mpk_path);
			break;

		}
		case keyextract: { // keyExtract
			argum.verifyRequiredParameters();
			PKG pkg = new PKG();
			System.out.print("Getting master keydata from: "
					+ argum.keystoragePath + " : ");
			KeyStorage ks = new KeyStorage(argum.keystoragePath);
			BigInteger[] keys = new BigInteger[3];
			int res = 0;
			try {
				res = ks.getKey(argum.domain, keys, argum.password);
			} catch (IllegalBlockSizeException ex) {
				Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null,
						ex);
			}
			if (res == 1) {
				System.out.println("OK.");
				pkg.init(keys[0], keys[1], keys[2]);
				System.out.print("Starting keyextract for: " + argum.id + " :");
				BigInteger encrSecrKey = pkg.keyExtract(argum.id);
				BigInteger signSecKey = pkg.signKeyExtract(argum.id);
				FileOutputStream skf = new FileOutputStream(argum.sk_path);
				skf.write(encrSecrKey.toByteArray());
				FileOutputStream sks = new FileOutputStream(argum.sks_path);
				sks.write(signSecKey.toByteArray());
				skf.close();
				sks.close();
				System.out.println("Done.");

			} else
				System.out.println("keyextract failed");

			break;

		}
		case encrypt: {
			PKG pkg = new PKG();
			Client client = new Client();
			argum.verifyRequiredParameters();
			BigInteger MPK = Util.readKeyData(new FileInputStream(
					argum.mpk_path));
			BigInteger signSecretKey = (Util.readKeyData(new FileInputStream(
					argum.sks_path)));
			System.out.print("Encrypting and signing " + argum.in_path + " to "
					+ argum.recip + " : ");
			try {
				client.encryptData(argum.in_path, argum.out_path,
						client.genPkID(argum.recip, MPK), MPK, signSecretKey,
						pkg.getSigningPublicKey());
			} catch (IllegalBlockSizeException ex) {
				Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null,
						ex);
			} catch (BadPaddingException ex) {
				Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null,
						ex);
			}
			System.out.println("Done");
			break;
		}
		case decrypt: { // decrypt
			PKG pkg = new PKG();
			Client client = new Client();
			argum.verifyRequiredParameters();
			System.out.print("Decrypting and verify sign " + argum.in_path
					+ " from " + argum.sender + " to: " + argum.recip + " : ");
			BigInteger MPK = Util.readKeyData(new FileInputStream(
					argum.mpk_path));
			BigInteger encrSecretKey = (Util.readKeyData(new FileInputStream(
					argum.sk_path)));
			byte[] decryptData = null;
			try {
				decryptData = client.decryptData(argum.in_path, argum.out_path,
						argum.recip, argum.sender, encrSecretKey, MPK,
						pkg.getSigningPublicKey());
			} catch (IllegalBlockSizeException ex) {
				System.out.println("Decryption error: key are illegal");
			} catch (BadPaddingException ex) {
				System.out.println("Decryption error: key are illegal");
			}
			if (decryptData == null) {
				System.out.println("Sign verification error");
			} else
				System.out.println("OK.");

			break;
		}

		case help: {
			Util.help();
			System.exit(1);
			break;

		}

		default: {
		}
		}
	}
}
