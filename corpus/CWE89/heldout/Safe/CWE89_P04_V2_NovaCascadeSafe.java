import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P04_V2_NovaCascadeSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    private String loadNovaCascade() {
        String data;
        if (IO.staticFive == 5) {
            data = "foo";
        } else {
            data = null;
        }
        return data;
    }

    public void runNovaCascade() throws SQLException {
        String data = loadNovaCascade();
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
}
