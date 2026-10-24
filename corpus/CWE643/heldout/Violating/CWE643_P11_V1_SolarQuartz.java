import java.util.HashMap;

import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P11_V1_SolarQuartz {

    public void runSolarQuartz() throws XPathExpressionException {
        String data;
        data = System.getenv("SOLAR_QUARTZ_ADD");
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE643_P11_V1_SolarQuartzSink()).sinkSolarQuartz(dataHashMap);
    }
}

class CWE643_P11_V1_SolarQuartzSink {

    public void sinkSolarQuartz(HashMap<Integer, String> dataHashMap) throws XPathExpressionException {
        String data = dataHashMap.get(2);
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
