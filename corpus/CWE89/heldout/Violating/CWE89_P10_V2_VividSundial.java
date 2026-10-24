import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P10_V2_VividSundial {
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    public static String data;

    public void runVividSundial() throws SQLException {
        if (PRIVATE_STATIC_FINAL_TRUE) {
            data = System.getenv("VIVID_SUNDIAL_FILTER");
        } else {
            data = null;
        }
        (new CWE89_P10_V2_VividSundialSink()).queryVividSundial();
    }
}

class CWE89_P10_V2_VividSundialSink {
    public void queryVividSundial() throws SQLException {
        String data = CWE89_P10_V2_VividSundial.data;
        Connection vividSundialConnection = DriverManager.getConnection("jdbc:hsqldb:mem:vividSundial");
        Statement vividSundialStatement = null;
        ResultSet vividSundialRows = null;
        try {
            vividSundialStatement = vividSundialConnection.createStatement();
            vividSundialRows = vividSundialStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(vividSundialRows.getRow());
        } finally {
            if (vividSundialRows != null) {
                vividSundialRows.close();
            }
            if (vividSundialStatement != null) {
                vividSundialStatement.close();
            }
            vividSundialConnection.close();
        }
    }
}
