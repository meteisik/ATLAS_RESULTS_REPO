import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P12_V2_ArcticLanternSafe {

    public void runArcticLantern() throws SQLException {
        String data;
        if (5 == 5) {
            data = "foo";
        } else {
            data = null;
        }
        CWE89_P12_V2_ArcticLanternSafeBase baseObject = new CWE89_P12_V2_ArcticLanternSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE89_P12_V2_ArcticLanternSafeBase {
    public abstract void action(String data) throws SQLException;
}

class CWE89_P12_V2_ArcticLanternSafeSink extends CWE89_P12_V2_ArcticLanternSafeBase {
    public void action(String data) throws SQLException {
        Connection arcticLanternConnection = DriverManager.getConnection("jdbc:hsqldb:mem:arcticLantern");
        Statement arcticLanternStatement = null;
        ResultSet arcticLanternRows = null;
        try {
            arcticLanternStatement = arcticLanternConnection.createStatement();
            arcticLanternRows = arcticLanternStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(arcticLanternRows.getRow());
        } finally {
            if (arcticLanternRows != null) {
                arcticLanternRows.close();
            }
            if (arcticLanternStatement != null) {
                arcticLanternStatement.close();
            }
            arcticLanternConnection.close();
        }
    }
}
