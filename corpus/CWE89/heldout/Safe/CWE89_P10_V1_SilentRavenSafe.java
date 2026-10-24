import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P10_V1_SilentRavenSafe {

    public static String data;

    public void runSilentRaven() throws SQLException {
        data = "foo";
        (new CWE89_P10_V1_SilentRavenSafeSink()).querySilentRaven();
    }
}

class CWE89_P10_V1_SilentRavenSafeSink {
    public void querySilentRaven() throws SQLException {
        String data = CWE89_P10_V1_SilentRavenSafe.data;
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
