import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P06_V2_SaffronQuartz {

    public void runSaffronQuartz() throws XPathExpressionException {
        String data;
        switch (7) {
        case 7:
            data = System.getenv("SAFFRON_QUARTZ_ADD");
            break;
        default:
            data = null;
            break;
        }
        (new CWE643_P06_V2_SaffronQuartzSink()).sinkSaffronQuartz(data);
    }
}

class CWE643_P06_V2_SaffronQuartzSink {

    public void sinkSaffronQuartz(String data) throws XPathExpressionException {
        String saffronQuartzXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            saffronQuartzXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            saffronQuartzXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] saffronQuartzTokens = data.split("||");
            if (saffronQuartzTokens.length < 2) {
                return;
            }
            String saffronQuartzUser = saffronQuartzTokens[0];
            String saffronQuartzPass = saffronQuartzTokens[1];
            XPath saffronQuartzXPath = XPathFactory.newInstance().newXPath();
            InputSource saffronQuartzXml = new InputSource(saffronQuartzXmlFile);
            String saffronQuartzQuery = "//users/user[name/text()='" + saffronQuartzUser
                    + "' and pass/text()='" + saffronQuartzPass + "']" + "/secret/text()";
            String saffronQuartzSecret = (String) saffronQuartzXPath.evaluate(saffronQuartzQuery, saffronQuartzXml, XPathConstants.STRING);
            System.out.println(saffronQuartzSecret);
        }
    }
}
