import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P10_V2_AmberCascadeSafe {

    public static String data;

    public void runAmberCascade() throws XPathExpressionException {
        data = null;
        for (int j = 0; j < 1; j++) {
            data = "foo";
        }
        (new CWE643_P10_V2_AmberCascadeSafeSink()).sinkAmberCascade();
    }
}

class CWE643_P10_V2_AmberCascadeSafeSink {

    public void sinkAmberCascade() throws XPathExpressionException {
        String data = CWE643_P10_V2_AmberCascadeSafe.data;
        String amberCascadeXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            amberCascadeXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            amberCascadeXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] amberCascadeTokens = data.split("||");
            if (amberCascadeTokens.length < 2) {
                return;
            }
            String amberCascadeUser = amberCascadeTokens[0];
            String amberCascadePass = amberCascadeTokens[1];
            XPath amberCascadeXPath = XPathFactory.newInstance().newXPath();
            InputSource amberCascadeXml = new InputSource(amberCascadeXmlFile);
            String amberCascadeQuery = "//users/user[name/text()='" + amberCascadeUser
                    + "' and pass/text()='" + amberCascadePass + "']" + "/secret/text()";
            String amberCascadeSecret = (String) amberCascadeXPath.evaluate(amberCascadeQuery, amberCascadeXml, XPathConstants.STRING);
            System.out.println(amberCascadeSecret);
        }
    }
}
