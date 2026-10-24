import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P12_V2_ArcticLantern {

    public void runArcticLantern() throws SQLException {
        String data;
        if (5 == 5) {
            data = System.getenv("ARCTIC_LANTERN_FILTER");
        } else {
            data = null;
        }
        CWE89_P12_V2_ArcticLanternBase baseObject = new CWE89_P12_V2_ArcticLanternSink();
        baseObject.action(data);
    }
}

abstract class CWE89_P12_V2_ArcticLanternBase {
    public abstract void action(String data) throws SQLException;
}

class CWE89_P12_V2_ArcticLanternSink extends CWE89_P12_V2_ArcticLanternBase {
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
