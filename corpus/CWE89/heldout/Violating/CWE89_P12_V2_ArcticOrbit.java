import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P12_V2_ArcticOrbit {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    public void runArcticOrbit() throws SQLException {
        String data;
        if (PRIVATE_STATIC_FINAL_FIVE == 5) {
            data = System.getenv("ARCTIC_ORBIT_FILTER");
        } else {
            data = null;
        }
        CWE89_P12_V2_ArcticOrbitBase baseObject = new CWE89_P12_V2_ArcticOrbitSink();
        baseObject.action(data);
    }
}

abstract class CWE89_P12_V2_ArcticOrbitBase {
    public abstract void action(String data) throws SQLException;
}

class CWE89_P12_V2_ArcticOrbitSink extends CWE89_P12_V2_ArcticOrbitBase {
    public void action(String data) throws SQLException {
        Connection arcticOrbitConnection = DriverManager.getConnection("jdbc:hsqldb:mem:arcticOrbit");
        Statement arcticOrbitStatement = null;
        ResultSet arcticOrbitRows = null;
        try {
            arcticOrbitStatement = arcticOrbitConnection.createStatement();
            arcticOrbitRows = arcticOrbitStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(arcticOrbitRows.getRow());
        } finally {
            if (arcticOrbitRows != null) {
                arcticOrbitRows.close();
            }
            if (arcticOrbitStatement != null) {
                arcticOrbitStatement.close();
            }
            arcticOrbitConnection.close();
        }
    }
}
