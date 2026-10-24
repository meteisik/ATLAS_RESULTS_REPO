import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P10_V1_RuneHelixSafe {

    public static String data;

    public void runRuneHelix() throws XPathExpressionException {
        data = "foo";
        (new CWE643_P10_V1_RuneHelixSafeSink()).sinkRuneHelix();
    }
}

class CWE643_P10_V1_RuneHelixSafeSink {

    public void sinkRuneHelix() throws XPathExpressionException {
        String data = CWE643_P10_V1_RuneHelixSafe.data;
        String runeHelixXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            runeHelixXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            runeHelixXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] runeHelixTokens = data.split("||");
            if (runeHelixTokens.length < 2) {
                return;
            }
            String runeHelixUser = runeHelixTokens[0];
            String runeHelixPass = runeHelixTokens[1];
            XPath runeHelixXPath = XPathFactory.newInstance().newXPath();
            InputSource runeHelixXml = new InputSource(runeHelixXmlFile);
            String runeHelixQuery = "//users/user[name/text()='" + runeHelixUser
                    + "' and pass/text()='" + runeHelixPass + "']" + "/secret/text()";
            String runeHelixSecret = (String) runeHelixXPath.evaluate(runeHelixQuery, runeHelixXml, XPathConstants.STRING);
            System.out.println(runeHelixSecret);
        }
    }
}
