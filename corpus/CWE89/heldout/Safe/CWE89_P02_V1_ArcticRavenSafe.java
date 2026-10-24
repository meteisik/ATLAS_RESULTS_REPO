import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P02_V1_ArcticRavenSafe {

    public void runArcticRaven() throws SQLException {
        String dataCopy;
        {
            String data;
            data = "foo";
            dataCopy = data;
        }
        {
            String data = dataCopy;
            Connection arcticRavenConnection = DriverManager.getConnection("jdbc:hsqldb:mem:arcticRaven");
            Statement arcticRavenStatement = null;
            ResultSet arcticRavenRows = null;
            try {
                arcticRavenStatement = arcticRavenConnection.createStatement();
                arcticRavenRows = arcticRavenStatement.executeQuery("select * from users where name='" + data + "'");
                System.out.println(arcticRavenRows.getRow());
            } finally {
                if (arcticRavenRows != null) {
                    arcticRavenRows.close();
                }
                if (arcticRavenStatement != null) {
                    arcticRavenStatement.close();
                }
                arcticRavenConnection.close();
            }
        }
    }
}
