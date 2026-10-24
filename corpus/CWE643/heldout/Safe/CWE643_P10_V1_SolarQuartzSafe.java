import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P10_V1_SolarQuartzSafe {

    public static String data;

    public void runSolarQuartz() throws XPathExpressionException {
        data = "foo";
        (new CWE643_P10_V1_SolarQuartzSafeSink()).sinkSolarQuartz();
    }
}

class CWE643_P10_V1_SolarQuartzSafeSink {

    public void sinkSolarQuartz() throws XPathExpressionException {
        String data = CWE643_P10_V1_SolarQuartzSafe.data;
        String solarQuartzXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            solarQuartzXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            solarQuartzXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] solarQuartzTokens = data.split("||");
            if (solarQuartzTokens.length < 2) {
                return;
            }
            String solarQuartzUser = solarQuartzTokens[0];
            String solarQuartzPass = solarQuartzTokens[1];
            XPath solarQuartzXPath = XPathFactory.newInstance().newXPath();
            InputSource solarQuartzXml = new InputSource(solarQuartzXmlFile);
            String solarQuartzQuery = "//users/user[name/text()='" + solarQuartzUser
                    + "' and pass/text()='" + solarQuartzPass + "']" + "/secret/text()";
            String solarQuartzSecret = (String) solarQuartzXPath.evaluate(solarQuartzQuery, solarQuartzXml, XPathConstants.STRING);
            System.out.println(solarQuartzSecret);
        }
    }
}
