import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P10_V2_ArcticOrbit {

    public static String data;

    public void runArcticOrbit() throws SQLException {
        if (true) {
            data = System.getenv("ARCTIC_ORBIT_FILTER");
        } else {
            data = null;
        }
        (new CWE89_P10_V2_ArcticOrbitSink()).queryArcticOrbit();
    }
}

class CWE89_P10_V2_ArcticOrbitSink {
    public void queryArcticOrbit() throws SQLException {
        String data = CWE89_P10_V2_ArcticOrbit.data;
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
