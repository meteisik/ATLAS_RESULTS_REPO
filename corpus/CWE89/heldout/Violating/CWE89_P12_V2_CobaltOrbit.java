import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P12_V2_CobaltOrbit {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    public void runCobaltOrbit() throws SQLException {
        String data;
        if (PRIVATE_STATIC_FINAL_FIVE == 5) {
            data = System.getenv("COBALT_ORBIT_FILTER");
        } else {
            data = null;
        }
        CWE89_P12_V2_CobaltOrbitBase baseObject = new CWE89_P12_V2_CobaltOrbitSink();
        baseObject.action(data);
    }
}

abstract class CWE89_P12_V2_CobaltOrbitBase {
    public abstract void action(String data) throws SQLException;
}

class CWE89_P12_V2_CobaltOrbitSink extends CWE89_P12_V2_CobaltOrbitBase {
    public void action(String data) throws SQLException {
        Connection cobaltOrbitConnection = DriverManager.getConnection("jdbc:hsqldb:mem:cobaltOrbit");
        Statement cobaltOrbitStatement = null;
        ResultSet cobaltOrbitRows = null;
        try {
            cobaltOrbitStatement = cobaltOrbitConnection.createStatement();
            cobaltOrbitRows = cobaltOrbitStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(cobaltOrbitRows.getRow());
        } finally {
            if (cobaltOrbitRows != null) {
                cobaltOrbitRows.close();
            }
            if (cobaltOrbitStatement != null) {
                cobaltOrbitStatement.close();
            }
            cobaltOrbitConnection.close();
        }
    }
}
