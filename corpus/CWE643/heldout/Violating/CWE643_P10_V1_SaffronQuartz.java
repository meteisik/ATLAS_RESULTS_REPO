import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P10_V1_SaffronQuartz {

    public static String data;

    public void runSaffronQuartz() throws XPathExpressionException {
        data = System.getenv("SAFFRON_QUARTZ_ADD");
        (new CWE643_P10_V1_SaffronQuartzSink()).sinkSaffronQuartz();
    }
}

class CWE643_P10_V1_SaffronQuartzSink {

    public void sinkSaffronQuartz() throws XPathExpressionException {
        String data = CWE643_P10_V1_SaffronQuartz.data;
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
