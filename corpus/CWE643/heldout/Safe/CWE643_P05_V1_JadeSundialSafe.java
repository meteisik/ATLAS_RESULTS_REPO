import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P05_V1_JadeSundialSafe {

    private String jadeSundialData;

    private void sinkJadeSundial() throws XPathExpressionException {
        String data = jadeSundialData;
        String jadeSundialXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            jadeSundialXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            jadeSundialXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] jadeSundialTokens = data.split("||");
            if (jadeSundialTokens.length < 2) {
                return;
            }
            String jadeSundialUser = jadeSundialTokens[0];
            String jadeSundialPass = jadeSundialTokens[1];
            XPath jadeSundialXPath = XPathFactory.newInstance().newXPath();
            InputSource jadeSundialXml = new InputSource(jadeSundialXmlFile);
            String jadeSundialQuery = "//users/user[name/text()='" + jadeSundialUser
                    + "' and pass/text()='" + jadeSundialPass + "']" + "/secret/text()";
            String jadeSundialSecret = (String) jadeSundialXPath.evaluate(jadeSundialQuery, jadeSundialXml, XPathConstants.STRING);
            System.out.println(jadeSundialSecret);
        }
    }

    public void runJadeSundial() throws XPathExpressionException {
        String data;
        data = "foo";
        jadeSundialData = data;
        sinkJadeSundial();
    }
}
