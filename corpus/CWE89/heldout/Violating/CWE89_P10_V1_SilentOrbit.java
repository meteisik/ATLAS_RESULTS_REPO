import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P10_V1_SilentOrbit {

    public static String data;

    public void runSilentOrbit() throws SQLException {
        data = System.getenv("SILENT_ORBIT_FILTER");
        (new CWE89_P10_V1_SilentOrbitSink()).querySilentOrbit();
    }
}

class CWE89_P10_V1_SilentOrbitSink {
    public void querySilentOrbit() throws SQLException {
        String data = CWE89_P10_V1_SilentOrbit.data;
        Connection silentOrbitConnection = DriverManager.getConnection("jdbc:hsqldb:mem:silentOrbit");
        Statement silentOrbitStatement = null;
        ResultSet silentOrbitRows = null;
        try {
            silentOrbitStatement = silentOrbitConnection.createStatement();
            silentOrbitRows = silentOrbitStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(silentOrbitRows.getRow());
        } finally {
            if (silentOrbitRows != null) {
                silentOrbitRows.close();
            }
            if (silentOrbitStatement != null) {
                silentOrbitStatement.close();
            }
            silentOrbitConnection.close();
        }
    }
}
