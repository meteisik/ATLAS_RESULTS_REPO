import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P10_V1_SaffronCascadeSafe {

    public static String data;

    public void runSaffronCascade() throws XPathExpressionException {
        data = "foo";
        (new CWE643_P10_V1_SaffronCascadeSafeSink()).sinkSaffronCascade();
    }
}

class CWE643_P10_V1_SaffronCascadeSafeSink {

    public void sinkSaffronCascade() throws XPathExpressionException {
        String data = CWE643_P10_V1_SaffronCascadeSafe.data;
        String saffronCascadeXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            saffronCascadeXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            saffronCascadeXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] saffronCascadeTokens = data.split("||");
            if (saffronCascadeTokens.length < 2) {
                return;
            }
            String saffronCascadeUser = saffronCascadeTokens[0];
            String saffronCascadePass = saffronCascadeTokens[1];
            XPath saffronCascadeXPath = XPathFactory.newInstance().newXPath();
            InputSource saffronCascadeXml = new InputSource(saffronCascadeXmlFile);
            String saffronCascadeQuery = "//users/user[name/text()='" + saffronCascadeUser
                    + "' and pass/text()='" + saffronCascadePass + "']" + "/secret/text()";
            String saffronCascadeSecret = (String) saffronCascadeXPath.evaluate(saffronCascadeQuery, saffronCascadeXml, XPathConstants.STRING);
            System.out.println(saffronCascadeSecret);
        }
    }
}
