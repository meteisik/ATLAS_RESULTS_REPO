import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P07_V2_SaffronSignalSafe {

    public void runSaffronSignal() throws XPathExpressionException {
        String data;
        if (true) {
            data = (new CWE643_P07_V2_SaffronSignalSafeSource()).sourceSaffronSignal();
        } else {
            data = null;
        }
        String saffronSignalXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            saffronSignalXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            saffronSignalXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] saffronSignalTokens = data.split("||");
            if (saffronSignalTokens.length < 2) {
                return;
            }
            String saffronSignalUser = saffronSignalTokens[0];
            String saffronSignalPass = saffronSignalTokens[1];
            XPath saffronSignalXPath = XPathFactory.newInstance().newXPath();
            InputSource saffronSignalXml = new InputSource(saffronSignalXmlFile);
            String saffronSignalQuery = "//users/user[name/text()='" + saffronSignalUser
                    + "' and pass/text()='" + saffronSignalPass + "']" + "/secret/text()";
            String saffronSignalSecret = (String) saffronSignalXPath.evaluate(saffronSignalQuery, saffronSignalXml, XPathConstants.STRING);
            System.out.println(saffronSignalSecret);
        }
    }
}

class CWE643_P07_V2_SaffronSignalSafeSource {

    public String sourceSaffronSignal() {
        String data;
        data = "foo";
        return data;
    }
}
