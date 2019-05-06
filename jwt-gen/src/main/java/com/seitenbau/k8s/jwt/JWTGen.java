package com.seitenbau.k8s.jwt;

import com.seitenbau.k8s.jwt.service.JWT;
import com.seitenbau.k8s.jwt.service.KeyReader;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

public class JWTGen
{
  public static void main(String[] args)
  {
    String issuer = "not defined", subject = "not defined";
    String keyPath = "./config/private_key_pkcs8.pem";
    int expDate = 15;

    Options options = new Options();

    Option helpOpt = Option.builder("h").longOpt("help").desc("print this help").build();
    options.addOption(helpOpt);

    Option subjectOpt = Option.builder("s").longOpt("subject").desc("token subject").hasArg().argName("name").build();
    options.addOption(subjectOpt);

    Option issuerOpt = Option.builder("i").longOpt("issuer").desc("token issuer").hasArg().argName("name").build();
    options.addOption(issuerOpt);

    Option expDateOpt = Option.builder("e")
                              .longOpt("expire")
                              .desc("days until expiration")
                              .hasArg()
                              .argName("days")
                              .build();
    options.addOption(expDateOpt);

    Option keyPathOpt = Option.builder("f")
                              .longOpt("key-file")
                              .desc("file name with path")
                              .hasArg()
                              .argName("file")
                              .build();
    options.addOption(keyPathOpt);

    CommandLineParser parser = new DefaultParser();
    try
    {
      CommandLine cmd = parser.parse(options, args);

      if (cmd.hasOption("help") || args.length == 0)
      {
        new HelpFormatter().printHelp("seitenbau jwt token tool", options);
        return;
      }


      if (cmd.hasOption("subject"))
      {
        subject = cmd.getOptionValue("subject");
      }

      if (cmd.hasOption("issuer"))
      {
        issuer = cmd.getOptionValue("issuer");
      }

      if (cmd.hasOption("key-file"))
      {
        keyPath = cmd.getOptionValue("key-file");
      }

      if (cmd.hasOption("expire"))
      {
        try
        {
          expDate = Integer.parseInt(cmd.getOptionValue("expire"));
        }
        catch (Exception e)
        {
          System.err.println("Value for expiration date not a number - using default value.");
        }
      }

      KeyReader keyReader = new KeyReader();

      JWT jwt = new JWT();
      jwt.setPrivateKey(keyReader.readPrivateKey(keyPath));
      System.out.println(jwt.buildToken(subject, issuer, expDate, ""));

    }
    catch (ParseException | NoSuchAlgorithmException | IOException | InvalidKeySpecException e)
    {
      System.err.println(e.getMessage());
    }
  }
}
