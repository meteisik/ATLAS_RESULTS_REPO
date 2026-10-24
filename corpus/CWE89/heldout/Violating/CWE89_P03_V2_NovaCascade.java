import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P03_V2_NovaCascade {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    private void queryNovaCascade(String data) throws SQLException {
        Connection novaCascadeConnection = DriverManager.getConnection("jdbc:hsqldb:mem:novaCascade");
        Statement novaCascadeStatement = null;
        ResultSet novaCascadeRows = null;
        try {
            novaCascadeStatement = novaCascadeConnection.createStatement();
            novaCascadeRows = novaCascadeStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(novaCascadeRows.getRow());
        } finally {
            if (novaCascadeRows != null) {
                novaCascadeRows.close();
            }
            if (novaCascadeStatement != null) {
                novaCascadeStatement.close();
            }
            novaCascadeConnection.close();
        }
    }

    public void runNovaCascade() throws SQLException {
        String data;
        if (IO.staticReturnsTrue()) {
            data = System.getenv("NOVA_CASCADE_FILTER");
        } else {
            data = null;
        }
        queryNovaCascade(data);
    }
}
