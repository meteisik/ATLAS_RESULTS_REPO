import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P02_V2_JadeFlareSafe {

    public void runJadeFlare() throws SQLException {
        String dataCopy;
        {
            String data;
            if (5 == 5) {
                data = "foo";
            } else {
                data = null;
            }
            dataCopy = data;
        }
        {
            String data = dataCopy;
            Connection jadeFlareConnection = DriverManager.getConnection("jdbc:hsqldb:mem:jadeFlare");
            Statement jadeFlareStatement = null;
            ResultSet jadeFlareRows = null;
            try {
                jadeFlareStatement = jadeFlareConnection.createStatement();
                jadeFlareRows = jadeFlareStatement.executeQuery("select * from users where name='" + data + "'");
                System.out.println(jadeFlareRows.getRow());
            } finally {
                if (jadeFlareRows != null) {
                    jadeFlareRows.close();
                }
                if (jadeFlareStatement != null) {
                    jadeFlareStatement.close();
                }
                jadeFlareConnection.close();
            }
        }
    }
}
