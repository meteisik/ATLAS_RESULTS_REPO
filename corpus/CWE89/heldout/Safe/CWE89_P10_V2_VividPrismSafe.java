import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P10_V2_VividPrismSafe {

    public static String data;

    public void runVividPrism() throws SQLException {
        if (true) {
            data = "foo";
        } else {
            data = null;
        }
        (new CWE89_P10_V2_VividPrismSafeSink()).queryVividPrism();
    }
}

class CWE89_P10_V2_VividPrismSafeSink {
    public void queryVividPrism() throws SQLException {
        String data = CWE89_P10_V2_VividPrismSafe.data;
        Connection vividPrismConnection = DriverManager.getConnection("jdbc:hsqldb:mem:vividPrism");
        Statement vividPrismStatement = null;
        ResultSet vividPrismRows = null;
        try {
            vividPrismStatement = vividPrismConnection.createStatement();
            vividPrismRows = vividPrismStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(vividPrismRows.getRow());
        } finally {
            if (vividPrismRows != null) {
                vividPrismRows.close();
            }
            if (vividPrismStatement != null) {
                vividPrismStatement.close();
            }
            vividPrismConnection.close();
        }
    }
}
