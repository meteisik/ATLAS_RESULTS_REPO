import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P12_V2_CrimsonRavenSafe {

    public void runCrimsonRaven() throws SQLException {
        String data;
        if (true) {
            data = "foo";
        } else {
            data = null;
        }
        CWE89_P12_V2_CrimsonRavenSafeBase baseObject = new CWE89_P12_V2_CrimsonRavenSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE89_P12_V2_CrimsonRavenSafeBase {
    public abstract void action(String data) throws SQLException;
}

class CWE89_P12_V2_CrimsonRavenSafeSink extends CWE89_P12_V2_CrimsonRavenSafeBase {
    public void action(String data) throws SQLException {
        Connection crimsonRavenConnection = DriverManager.getConnection("jdbc:hsqldb:mem:crimsonRaven");
        Statement crimsonRavenStatement = null;
        ResultSet crimsonRavenRows = null;
        try {
            crimsonRavenStatement = crimsonRavenConnection.createStatement();
            crimsonRavenRows = crimsonRavenStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(crimsonRavenRows.getRow());
        } finally {
            if (crimsonRavenRows != null) {
                crimsonRavenRows.close();
            }
            if (crimsonRavenStatement != null) {
                crimsonRavenStatement.close();
            }
            crimsonRavenConnection.close();
        }
    }
}
