import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P03_V2_JadeCascadeSafe {

    private void sinkJadeCascade(String data) throws XPathExpressionException {
        String jadeCascadeXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            jadeCascadeXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            jadeCascadeXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] jadeCascadeTokens = data.split("||");
            if (jadeCascadeTokens.length < 2) {
                return;
            }
            String jadeCascadeUser = jadeCascadeTokens[0];
            String jadeCascadePass = jadeCascadeTokens[1];
            XPath jadeCascadeXPath = XPathFactory.newInstance().newXPath();
            InputSource jadeCascadeXml = new InputSource(jadeCascadeXmlFile);
            String jadeCascadeQuery = "//users/user[name/text()='" + jadeCascadeUser
                    + "' and pass/text()='" + jadeCascadePass + "']" + "/secret/text()";
            String jadeCascadeSecret = (String) jadeCascadeXPath.evaluate(jadeCascadeQuery, jadeCascadeXml, XPathConstants.STRING);
            System.out.println(jadeCascadeSecret);
        }
    }

    public void runJadeCascade() throws XPathExpressionException {
        String data;
        if (5 == 5) {
            data = "foo";
        } else {
            data = null;
        }
        sinkJadeCascade(data);
    }
}
