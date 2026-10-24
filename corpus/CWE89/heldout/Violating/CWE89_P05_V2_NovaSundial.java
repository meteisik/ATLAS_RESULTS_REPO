import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P05_V2_NovaSundial {
    private static boolean privateTrue = true;

    private String novaSundialData;

    private void queryNovaSundial() throws SQLException {
        String data = novaSundialData;
        Connection novaSundialConnection = DriverManager.getConnection("jdbc:hsqldb:mem:novaSundial");
        Statement novaSundialStatement = null;
        ResultSet novaSundialRows = null;
        try {
            novaSundialStatement = novaSundialConnection.createStatement();
            novaSundialRows = novaSundialStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(novaSundialRows.getRow());
        } finally {
            if (novaSundialRows != null) {
                novaSundialRows.close();
            }
            if (novaSundialStatement != null) {
                novaSundialStatement.close();
            }
            novaSundialConnection.close();
        }
    }

    public void runNovaSundial() throws SQLException {
        String data;
        if (privateTrue) {
            data = System.getenv("NOVA_SUNDIAL_FILTER");
        } else {
            data = null;
        }
        novaSundialData = data;
        queryNovaSundial();
    }
}
