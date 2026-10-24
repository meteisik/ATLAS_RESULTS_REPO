import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P12_V1_ArcticHarborSafe {

    public void runArcticHarbor() throws SQLException {
        String data;
        data = "foo";
        CWE89_P12_V1_ArcticHarborSafeBase baseObject = new CWE89_P12_V1_ArcticHarborSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE89_P12_V1_ArcticHarborSafeBase {
    public abstract void action(String data) throws SQLException;
}

class CWE89_P12_V1_ArcticHarborSafeSink extends CWE89_P12_V1_ArcticHarborSafeBase {
    public void action(String data) throws SQLException {
        Connection arcticHarborConnection = DriverManager.getConnection("jdbc:hsqldb:mem:arcticHarbor");
        Statement arcticHarborStatement = null;
        ResultSet arcticHarborRows = null;
        try {
            arcticHarborStatement = arcticHarborConnection.createStatement();
            arcticHarborRows = arcticHarborStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(arcticHarborRows.getRow());
        } finally {
            if (arcticHarborRows != null) {
                arcticHarborRows.close();
            }
            if (arcticHarborStatement != null) {
                arcticHarborStatement.close();
            }
            arcticHarborConnection.close();
        }
    }
}
