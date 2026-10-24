import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P10_V2_ArcticLantern {

    public static String data;

    public void runArcticLantern() throws SQLException {
        switch (7) {
        case 7:
            data = System.getenv("ARCTIC_LANTERN_FILTER");
            break;
        default:
            data = null;
            break;
        }
        (new CWE89_P10_V2_ArcticLanternSink()).queryArcticLantern();
    }
}

class CWE89_P10_V2_ArcticLanternSink {
    public void queryArcticLantern() throws SQLException {
        String data = CWE89_P10_V2_ArcticLantern.data;
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
