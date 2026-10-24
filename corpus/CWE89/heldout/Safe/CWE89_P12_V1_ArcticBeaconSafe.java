import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P12_V1_ArcticBeaconSafe {

    public void runArcticBeacon() throws SQLException {
        String data;
        data = "foo";
        CWE89_P12_V1_ArcticBeaconSafeBase baseObject = new CWE89_P12_V1_ArcticBeaconSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE89_P12_V1_ArcticBeaconSafeBase {
    public abstract void action(String data) throws SQLException;
}

class CWE89_P12_V1_ArcticBeaconSafeSink extends CWE89_P12_V1_ArcticBeaconSafeBase {
    public void action(String data) throws SQLException {
        Connection arcticBeaconConnection = DriverManager.getConnection("jdbc:hsqldb:mem:arcticBeacon");
        Statement arcticBeaconStatement = null;
        ResultSet arcticBeaconRows = null;
        try {
            arcticBeaconStatement = arcticBeaconConnection.createStatement();
            arcticBeaconRows = arcticBeaconStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(arcticBeaconRows.getRow());
        } finally {
            if (arcticBeaconRows != null) {
                arcticBeaconRows.close();
            }
            if (arcticBeaconStatement != null) {
                arcticBeaconStatement.close();
            }
            arcticBeaconConnection.close();
        }
    }
}
