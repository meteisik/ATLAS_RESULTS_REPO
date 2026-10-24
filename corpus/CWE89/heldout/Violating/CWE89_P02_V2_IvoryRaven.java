import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P02_V2_IvoryRaven {

    public void runIvoryRaven() throws SQLException {
        String dataCopy;
        {
            String data;
            switch (7) {
            case 7:
                data = System.getenv("IVORY_RAVEN_FILTER");
                break;
            default:
                data = null;
                break;
            }
            dataCopy = data;
        }
        {
            String data = dataCopy;
            Connection ivoryRavenConnection = DriverManager.getConnection("jdbc:hsqldb:mem:ivoryRaven");
            Statement ivoryRavenStatement = null;
            ResultSet ivoryRavenRows = null;
            try {
                ivoryRavenStatement = ivoryRavenConnection.createStatement();
                ivoryRavenRows = ivoryRavenStatement.executeQuery("select * from users where name='" + data + "'");
                System.out.println(ivoryRavenRows.getRow());
            } finally {
                if (ivoryRavenRows != null) {
                    ivoryRavenRows.close();
                }
                if (ivoryRavenStatement != null) {
                    ivoryRavenStatement.close();
                }
                ivoryRavenConnection.close();
            }
        }
    }
}
