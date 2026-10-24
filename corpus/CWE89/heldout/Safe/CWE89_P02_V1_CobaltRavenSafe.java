import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P02_V1_CobaltRavenSafe {

    public void runCobaltRaven() throws SQLException {
        String dataCopy;
        {
            String data;
            data = "foo";
            dataCopy = data;
        }
        {
            String data = dataCopy;
            Connection cobaltRavenConnection = DriverManager.getConnection("jdbc:hsqldb:mem:cobaltRaven");
            Statement cobaltRavenStatement = null;
            ResultSet cobaltRavenRows = null;
            try {
                cobaltRavenStatement = cobaltRavenConnection.createStatement();
                cobaltRavenRows = cobaltRavenStatement.executeQuery("select * from users where name='" + data + "'");
                System.out.println(cobaltRavenRows.getRow());
            } finally {
                if (cobaltRavenRows != null) {
                    cobaltRavenRows.close();
                }
                if (cobaltRavenStatement != null) {
                    cobaltRavenStatement.close();
                }
                cobaltRavenConnection.close();
            }
        }
    }
}
