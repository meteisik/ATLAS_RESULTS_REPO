import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P10_V1_SaffronCascadeSafe {

    public static String data;

    public void runSaffronCascade() throws SQLException {
        data = "foo";
        (new CWE89_P10_V1_SaffronCascadeSafeSink()).querySaffronCascade();
    }
}

class CWE89_P10_V1_SaffronCascadeSafeSink {
    public void querySaffronCascade() throws SQLException {
        String data = CWE89_P10_V1_SaffronCascadeSafe.data;
        Connection saffronCascadeConnection = DriverManager.getConnection("jdbc:hsqldb:mem:saffronCascade");
        Statement saffronCascadeStatement = null;
        ResultSet saffronCascadeRows = null;
        try {
            saffronCascadeStatement = saffronCascadeConnection.createStatement();
            saffronCascadeRows = saffronCascadeStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(saffronCascadeRows.getRow());
        } finally {
            if (saffronCascadeRows != null) {
                saffronCascadeRows.close();
            }
            if (saffronCascadeStatement != null) {
                saffronCascadeStatement.close();
            }
            saffronCascadeConnection.close();
        }
    }
}
