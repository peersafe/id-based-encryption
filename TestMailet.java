/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package org.suai.testmailet;


import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Collection;
import java.util.Iterator;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.mail.BodyPart;
import javax.mail.MessagingException;
import javax.mail.Multipart;
import javax.mail.Part;
import javax.mail.internet.MimeMessage;
import org.apache.mailet.GenericMailet;
import org.apache.mailet.Mail;
import org.apache.mailet.MailAddress;
import org.apache.mailet.MailetConfig;
import org.apache.mailet.MailetContext;
import org.apache.mailet.RFC2822Headers;

/**
 *
 * @author foxneig
 */
public class TestMailet extends GenericMailet {

    private MailetConfig config;
    private FileWriter output;
    private String key;
    private String folder;
    private int num = 0;

   
    @Override
    public void destroy () {
        System.out.println ("Destroy");
        try {
            output.close();
        } catch (IOException ex) {
            Logger.getLogger(TestMailet.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    @Override
    public String getMailetInfo() {
        return "Test Mailet";
    }

    @Override
    public MailetConfig getMailetConfig() {
        return config;
    }

    @Override
    public void init(MailetConfig config) throws MessagingException {
    System.out.println ("Init");
    super.init(config);
    MailetContext context = config.getMailetContext();
    folder = getInitParameter("outputPath");
    this.key = getInitParameter("key");
 
   


    }
    public void saveFile (String filename, InputStream is) {
        System.out.println ("Saving "+filename);
        try {
            FileOutputStream fos = new FileOutputStream(folder + filename);
            byte[] buff = new byte[8];
            int i = 0;
            do {
                try {
                    i = is.read(buff);
                    fos.write(buff);
                } catch (IOException ex) {
                    log ("Cannot read from attaches");
                }

            } while (i != -1);
            fos.close();
            is.close();
        } catch (IOException ex) {
            Logger.getLogger(TestMailet.class.getName()).log(Level.SEVERE, null, ex);
        }


    }
    public String modifyTextBody (String text, String key) {
        byte[] bytes = text.getBytes();
        byte[] keyb = key.getBytes();
                //изменяем тело
        for (int i = 0; i < bytes.length; i++) bytes[i] = (byte) (bytes[i] ^ keyb[i % keyb.length]);
        String encrMessage =  new String (bytes);
        return encrMessage;

    }
    public byte[] modifyAttachments (InputStream is, String key) throws IOException {
        int i = 0;
        byte [] buff = new byte [8];
        byte[] keyb = key.getBytes();
        ByteArrayOutputStream os = new ByteArrayOutputStream ();
          do {
                try {
                    i = is.read(buff);
                    os.write(buff);
                } catch (IOException ex) {
                    log ("Cannot read from attaches");
                }

            } while (i != -1);
        System.out.println ("Modify ended");
        byte[] bytes = os.toByteArray();
        os.close();
        is.close();
         System.out.println ("Length " + bytes.length);
        for (int j = 0; j < bytes.length; j++) {
            bytes[j] = (byte) (bytes[j] ^ keyb[j % keyb.length]);
          //  System.out.println (""+j);
        }
       

        return bytes;


    }

    public void service(Mail mail) throws MessagingException {
        System.out.println ("MyAppletStarted!!!");
        MimeMessage message = mail.getMessage();
        String contentType = message.getContentType();
        System.out.println (contentType);
        if (message.isMimeType("text/plain")) {
            try {
                System.out.println ("Extract data");
                MailAddress from = mail.getSender();
                Collection <MailAddress> to = mail.getRecipients();
                String suser = from.getUser();
                String shost = from.getHost();
                String seadr = suser+"@"+shost;
                String text = (String) message.getContent();
                output = new FileWriter(folder+seadr+""+(++num)+".txt");


                
                output.write("E-mail FROM: " + seadr +"\n");
                output.write ("E-mail TO: ");


                for (Iterator<MailAddress> iterator = to.iterator(); iterator.hasNext() ;) {
                    output.write(iterator.next().toString()+",");
                }
                output.write("E-mail text body: " +text);
               
                System.out.println ("Changes mail-body");
                
                message.setContent(modifyTextBody(text,key), contentType);
                message.setHeader(RFC2822Headers.CONTENT_TYPE, contentType);
                message.saveChanges();
                output.close();
            } catch (IOException ex) {
                log ("Unable to get text from "+mail.getName());
            }

        }
        else if (message.isMimeType("multipart/mixed") ||message.isMimeType("multipart/related")  ) {

            try {
                // здесь надо сохранить аттачи
                Multipart mp = (Multipart) message.getContent();

                System.out.println ("PartsNum: "+mp.getCount());

                for (int i = 0, n = mp.getCount(); i < n; i++) {
                    Part part = mp.getBodyPart(i);
                   
                    if (part.isMimeType("text/plain")) {
                     System.out.println ("Try to modify text");
               //      message.setContent(modifyTextBody((String)part.getContent(),key), part.getContentType());
               //      message.saveChanges();
                     part.setContent(modifyTextBody((String)part.getContent(),key), part.getContentType());
                     boolean removeBodyPart = mp.removeBodyPart((BodyPart) part);
                     System.out.println ("Removed: "+removeBodyPart);
                     mp.addBodyPart((BodyPart) part,i);
                     message.setContent(mp);

                     
                    }
                    else {

                    String disposition = part.getDisposition();
                    System.out.println ("Disposition "+disposition);
                    if ((disposition != null) && ((disposition.equals(Part.ATTACHMENT) || (disposition.equals(Part.INLINE))))) {
                        saveFile(part.getFileName(), part.getInputStream());
                        System.out.println ("Try to modify attache");
                        byte [] new_attach = this.modifyAttachments(part.getInputStream(), key);
                        part.setContent(new_attach, part.getContentType());
                        part.setFileName("encrypted"+i);
                        boolean removeBodyPart = mp.removeBodyPart((BodyPart) part);
                        System.out.println ("Removed: "+removeBodyPart);
                        mp.addBodyPart((BodyPart) part,i);

                        message.setContent(mp);
                       


                      
                     System.out.println ("Attache is modified");

                        

                    }
                    }
                }
            } catch (IOException ex) {
               log("Cannot to get attaches");
            }
        }
         message.setHeader(RFC2822Headers.CONTENT_TYPE, contentType);
         message.saveChanges();
        System.out.println ("Ended");
        
        



    }


}
