import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P06_V2_SilentOrbitSafe {
    private static int privateFive = 5;

    public void runSilentOrbit() throws SQLException {
        String data;
        if (privateFive == 5) {
            data = "foo";
        } else {
            data = null;
        }
        (new CWE89_P06_V2_SilentOrbitSafeSink()).querySilentOrbit(data);
    }
}

class CWE89_P06_V2_SilentOrbitSafeSink {
    public void querySilentOrbit(String data) throws SQLException {
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
