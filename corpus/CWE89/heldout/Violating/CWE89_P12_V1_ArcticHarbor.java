import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P12_V1_ArcticHarbor {

    public void runArcticHarbor() throws SQLException {
        String data;
        data = System.getenv("ARCTIC_HARBOR_FILTER");
        CWE89_P12_V1_ArcticHarborBase baseObject = new CWE89_P12_V1_ArcticHarborSink();
        baseObject.action(data);
    }
}

abstract class CWE89_P12_V1_ArcticHarborBase {
    public abstract void action(String data) throws SQLException;
}

class CWE89_P12_V1_ArcticHarborSink extends CWE89_P12_V1_ArcticHarborBase {
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
