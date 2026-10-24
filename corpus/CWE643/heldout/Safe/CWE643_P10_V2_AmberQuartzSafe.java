import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P10_V2_AmberQuartzSafe {
    private static int privateFive = 5;

    public static String data;

    public void runAmberQuartz() throws XPathExpressionException {
        if (privateFive == 5) {
            data = "foo";
        } else {
            data = null;
        }
        (new CWE643_P10_V2_AmberQuartzSafeSink()).sinkAmberQuartz();
    }
}

class CWE643_P10_V2_AmberQuartzSafeSink {

    public void sinkAmberQuartz() throws XPathExpressionException {
        String data = CWE643_P10_V2_AmberQuartzSafe.data;
        String amberQuartzXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            amberQuartzXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            amberQuartzXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] amberQuartzTokens = data.split("||");
            if (amberQuartzTokens.length < 2) {
                return;
            }
            String amberQuartzUser = amberQuartzTokens[0];
            String amberQuartzPass = amberQuartzTokens[1];
            XPath amberQuartzXPath = XPathFactory.newInstance().newXPath();
            InputSource amberQuartzXml = new InputSource(amberQuartzXmlFile);
            String amberQuartzQuery = "//users/user[name/text()='" + amberQuartzUser
                    + "' and pass/text()='" + amberQuartzPass + "']" + "/secret/text()";
            String amberQuartzSecret = (String) amberQuartzXPath.evaluate(amberQuartzQuery, amberQuartzXml, XPathConstants.STRING);
            System.out.println(amberQuartzSecret);
        }
    }
}
