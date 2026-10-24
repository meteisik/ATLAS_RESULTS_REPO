import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P01_V2_GoldenPrism {

    public void runGoldenPrism() throws SQLException {
        String data;
        switch (7) {
        case 7:
            data = System.getenv("GOLDEN_PRISM_FILTER");
            break;
        default:
            data = null;
            break;
        }
        Connection goldenPrismConnection = DriverManager.getConnection("jdbc:hsqldb:mem:goldenPrism");
        Statement goldenPrismStatement = null;
        ResultSet goldenPrismRows = null;
        try {
            goldenPrismStatement = goldenPrismConnection.createStatement();
            goldenPrismRows = goldenPrismStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(goldenPrismRows.getRow());
        } finally {
            if (goldenPrismRows != null) {
                goldenPrismRows.close();
            }
            if (goldenPrismStatement != null) {
                goldenPrismStatement.close();
            }
            goldenPrismConnection.close();
        }
    }
}
