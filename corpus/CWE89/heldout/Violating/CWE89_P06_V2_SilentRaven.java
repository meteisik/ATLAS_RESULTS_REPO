import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P06_V2_SilentRaven {
    private static boolean privateReturnsTrue() { return true; }

    public void runSilentRaven() throws SQLException {
        String data;
        if (privateReturnsTrue()) {
            data = System.getenv("SILENT_RAVEN_FILTER");
        } else {
            data = null;
        }
        (new CWE89_P06_V2_SilentRavenSink()).querySilentRaven(data);
    }
}

class CWE89_P06_V2_SilentRavenSink {
    public void querySilentRaven(String data) throws SQLException {
        Connection silentRavenConnection = DriverManager.getConnection("jdbc:hsqldb:mem:silentRaven");
        Statement silentRavenStatement = null;
        ResultSet silentRavenRows = null;
        try {
            silentRavenStatement = silentRavenConnection.createStatement();
            silentRavenRows = silentRavenStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(silentRavenRows.getRow());
        } finally {
            if (silentRavenRows != null) {
                silentRavenRows.close();
            }
            if (silentRavenStatement != null) {
                silentRavenStatement.close();
            }
            silentRavenConnection.close();
        }
    }
}
