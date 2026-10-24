import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P10_V2_ArcticLanternSafe {

    public static String data;

    public void runArcticLantern() throws SQLException {
        switch (7) {
        case 7:
            data = "foo";
            break;
        default:
            data = null;
            break;
        }
        (new CWE89_P10_V2_ArcticLanternSafeSink()).queryArcticLantern();
    }
}

class CWE89_P10_V2_ArcticLanternSafeSink {
    public void queryArcticLantern() throws SQLException {
        String data = CWE89_P10_V2_ArcticLanternSafe.data;
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
