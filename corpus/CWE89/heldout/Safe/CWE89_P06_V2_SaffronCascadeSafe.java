import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P06_V2_SaffronCascadeSafe {
    private static boolean privateReturnsTrue() { return true; }

    public void runSaffronCascade() throws SQLException {
        String data;
        if (privateReturnsTrue()) {
            data = "foo";
        } else {
            data = null;
        }
        (new CWE89_P06_V2_SaffronCascadeSafeSink()).querySaffronCascade(data);
    }
}

class CWE89_P06_V2_SaffronCascadeSafeSink {
    public void querySaffronCascade(String data) throws SQLException {
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
