import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P01_V2_GoldenCipherSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void runGoldenCipher() throws SQLException {
        String data;
        if (IO.staticTrue) {
            data = "foo";
        } else {
            data = null;
        }
        Connection goldenCipherConnection = DriverManager.getConnection("jdbc:hsqldb:mem:goldenCipher");
        Statement goldenCipherStatement = null;
        ResultSet goldenCipherRows = null;
        try {
            goldenCipherStatement = goldenCipherConnection.createStatement();
            goldenCipherRows = goldenCipherStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(goldenCipherRows.getRow());
        } finally {
            if (goldenCipherRows != null) {
                goldenCipherRows.close();
            }
            if (goldenCipherStatement != null) {
                goldenCipherStatement.close();
            }
            goldenCipherConnection.close();
        }
    }
}
