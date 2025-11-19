#include <gtest/gtest.h>
#include "../udpsocket.h"

TEST(UDPSocketTest, CanConstruct) {
    UDPSocket s;
    SUCCEED();
}

TEST(UDPSocketTest, BindInvalidAddressFails) {
    UDPSocket s;
    int rc = s.Bind("999.999.999.999", 1234);
    EXPECT_LT(rc, 0);
}
