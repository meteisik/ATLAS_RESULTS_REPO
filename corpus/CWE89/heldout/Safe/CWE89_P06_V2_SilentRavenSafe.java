import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P06_V2_SilentRavenSafe {
    private static boolean privateReturnsTrue() { return true; }

    public void runSilentRaven() throws SQLException {
        String data;
        if (privateReturnsTrue()) {
            data = "foo";
        } else {
            data = null;
        }
        (new CWE89_P06_V2_SilentRavenSafeSink()).querySilentRaven(data);
    }
}

class CWE89_P06_V2_SilentRavenSafeSink {
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
