import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P06_V2_SaffronSundialSafe {

    public void runSaffronSundial() throws XPathExpressionException {
        String data;
        data = null;
        for (int j = 0; j < 1; j++) {
            data = "foo";
        }
        (new CWE643_P06_V2_SaffronSundialSafeSink()).sinkSaffronSundial(data);
    }
}

class CWE643_P06_V2_SaffronSundialSafeSink {

    public void sinkSaffronSundial(String data) throws XPathExpressionException {
        String saffronSundialXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            saffronSundialXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            saffronSundialXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] saffronSundialTokens = data.split("||");
            if (saffronSundialTokens.length < 2) {
                return;
            }
            String saffronSundialUser = saffronSundialTokens[0];
            String saffronSundialPass = saffronSundialTokens[1];
            XPath saffronSundialXPath = XPathFactory.newInstance().newXPath();
            InputSource saffronSundialXml = new InputSource(saffronSundialXmlFile);
            String saffronSundialQuery = "//users/user[name/text()='" + saffronSundialUser
                    + "' and pass/text()='" + saffronSundialPass + "']" + "/secret/text()";
            String saffronSundialSecret = (String) saffronSundialXPath.evaluate(saffronSundialQuery, saffronSundialXml, XPathConstants.STRING);
            System.out.println(saffronSundialSecret);
        }
    }
}
